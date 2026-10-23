#!/usr/bin/env python3
"""
Monitor de memoria: le o uso de memoria pela API do Zabbix e, se passar do
limite, abre um chamado no GLPI automatizando o formulario web (sem API REST).

Pensado para rodar no Windows via Agendador de Tarefas / PowerShell, de tempos
em tempos (ex: a cada 5 minutos).

Requisitos:
    pip install requests

Configuracao (variaveis de ambiente):
    ZABBIX_URL       ex: http://161.35.63.175:81/api_jsonrpc.php
    ZABBIX_USER      seu login do Zabbix (view-only serve para LER)
    ZABBIX_PASS      sua senha do Zabbix
    ZABBIX_ITEM      nome do item de memoria (padrao: "Memory utilization")
    ZABBIX_HOST      (opcional) filtra pelo nome do host

    GLPI_URL         base do GLPI, ex: http://161.35.63.175/glpi  (SEM /apirest.php)
    GLPI_USER        usuario que o gestor te passou
    GLPI_PASS        senha desse usuario
    GLPI_ENTITY      (opcional) entities_id

    THRESHOLD        limite em % (padrao: 81)
    COOLDOWN_MIN     minutos entre chamados para nao floodar (padrao: 60)
    INSECURE         =1 para ignorar erro de certificado (servidor interno)
"""
import os
import re
import sys
import json
import datetime
import unicodedata
import urllib3
import requests

ZBX_URL   = os.environ.get("ZABBIX_URL", "").rstrip("/")
ZBX_USER  = os.environ.get("ZABBIX_USER", "")
ZBX_PASS  = os.environ.get("ZABBIX_PASS", "")
ZBX_ITEM  = os.environ.get("ZABBIX_ITEM", "vm.memory.utilization")  # chave (key_) do item
ZBX_HOST  = os.environ.get("ZABBIX_HOST", "")

GLPI_URL    = os.environ.get("GLPI_URL", "").rstrip("/")
GLPI_USER   = os.environ.get("GLPI_USER", "")
GLPI_PASS   = os.environ.get("GLPI_PASS", "")
GLPI_ENTITY = os.environ.get("GLPI_ENTITY")

THRESHOLD    = float(os.environ.get("THRESHOLD", "81"))
COOLDOWN_MIN = int(os.environ.get("COOLDOWN_MIN", "60"))   # espacamento minimo entre chamados (min)
INSECURE     = bool(os.environ.get("INSECURE"))

ERRO_BACKOFF_BASE = int(os.environ.get("ERRO_BACKOFF_BASE", "90"))   # espera apos 1 erro (min)
ERRO_BACKOFF_MAX  = int(os.environ.get("ERRO_BACKOFF_MAX", "360"))   # teto da espera (min)

WEBAPP_URL = os.environ.get("WEBAPP_URL", "")          # URL /exec do Web App do Apps Script
COL_ID     = os.environ.get("COL_ID", "ID")            # nome da coluna com o numero do chamado
COL_TITULO = os.environ.get("COL_TITULO", "Título")    # nome da coluna com o titulo/assunto
COL_STATUS = os.environ.get("COL_STATUS", "Status")    # nome da coluna com o status
TITULO_KEYWORD    = os.environ.get("TITULO_KEYWORD", "memoria alta")    # frase discreta que so os chamados do script tem
STATUS_RESOLVIDOS = os.environ.get("STATUS_RESOLVIDOS", "Solucionado,Fechado")  # status que contam como resolvido

VERIFY = not INSECURE
if INSECURE:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_BASE_DIR  = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(_BASE_DIR, "estado_alerta.json")
LOG_FILE   = os.path.join(_BASE_DIR, "monitor.log")


def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    linha = f"[{ts}] {msg}"
    print(linha)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(linha + "\n")
    except Exception:
        pass


def zbx_call(method, params, token=None):
    headers = {"Content-Type": "application/json-rpc"}
    if token:
        # Zabbix 6.4+ / 7.0: token vai no header Authorization.
        # Se seu Zabbix for < 6.4, remova esta linha e use params["auth"] = token.
        headers["Authorization"] = f"Bearer {token}"
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    r = requests.post(ZBX_URL, json=payload, headers=headers, verify=VERIFY, timeout=20)
    data = r.json()
    if "error" in data:
        raise RuntimeError(f"Zabbix {method}: {data['error']}")
    return data["result"]


def zbx_login():
    return zbx_call("user.login", {"username": ZBX_USER, "password": ZBX_PASS})


def zbx_memoria(token):
    itens = zbx_call("item.get", {
        "output": ["itemid", "name", "lastvalue"],
        "filter": {"key_": ZBX_ITEM},   # match exato pela chave (ex: vm.memory.utilization)
        "selectHosts": ["name"],
    }, token)
    if not itens:
        raise RuntimeError(f"Item com chave '{ZBX_ITEM}' nao encontrado no Zabbix.")

    if ZBX_HOST:
        filtrados = [i for i in itens if i.get("hosts") and i["hosts"][0]["name"] == ZBX_HOST]
        if not filtrados:
            nomes = ", ".join(sorted({i["hosts"][0]["name"] for i in itens if i.get("hosts")}))
            raise RuntimeError(f"Host '{ZBX_HOST}' nao encontrado. Hosts disponiveis: {nomes}")
        itens = filtrados

    melhor = None
    for i in itens:
        try:
            if float(i["lastvalue"]) > 0:
                melhor = i
                break
        except (ValueError, TypeError):
            continue
    if melhor is None:
        melhor = itens[0]

    host = melhor["hosts"][0]["name"] if melhor.get("hosts") else "?"
    return float(melhor["lastvalue"]), f"{melhor['name']} ({host})"


def zbx_logout(token):
    try:
        zbx_call("user.logout", [], token)
    except Exception:
        pass


def _csrf(html):
    # O token pode vir de tres jeitos, dependendo da versao/pagina do GLPI:
    #   <input name="_glpi_csrf_token" value="...">
    #   <meta property="glpi:csrf_token" content="...">
    #   value="..." antes do name (ordem invertida)
    padroes = (
        r'name="_glpi_csrf_token"[^>]*value="([a-f0-9]+)"',
        r'value="([a-f0-9]+)"[^>]*name="_glpi_csrf_token"',
        r'property="glpi:csrf_token"[^>]*content="([a-f0-9]+)"',
        r'content="([a-f0-9]+)"[^>]*property="glpi:csrf_token"',
    )
    for pat in padroes:
        m = re.search(pat, html)
        if m:
            return m.group(1)
    raise RuntimeError("Nao achei o _glpi_csrf_token na pagina do GLPI.")


def glpi_login():
    s = requests.Session()
    s.verify = VERIFY
    r = s.get(GLPI_URL + "/index.php", timeout=20)
    token = _csrf(r.text)
    r = s.post(GLPI_URL + "/front/login.php", data={
        "login_name": GLPI_USER,
        "login_password": GLPI_PASS,
        "_glpi_csrf_token": token,
        "submit": "Post",
    }, timeout=20)

    if "login_password" in r.text and "front/central.php" not in r.url:
        raise RuntimeError("Login no GLPI falhou (confira usuario/senha).")
    return s


def glpi_abrir_chamado(s, titulo, descricao, urgencia=4):
    r = s.get(GLPI_URL + "/front/ticket.form.php", timeout=20)
    token = _csrf(r.text)
    dados = {
        "_glpi_csrf_token": token,
        "name": titulo,
        "content": descricao,
        "urgency": str(urgencia),   # 1..5
        "type": "1",                # 1 = Incidente
        "add": "Adicionar",         # botao de submit do formulario
    }
    if GLPI_ENTITY:
        dados["entities_id"] = str(GLPI_ENTITY)

    # Nao segue o redirect: assim capturamos a resposta REAL do POST.
    # Sucesso no GLPI = 302/303 com Location apontando para o chamado criado.
    # 403 = POST recusado (tipicamente CSRF). 200 = formulario recarregou com erro.
    r = s.post(GLPI_URL + "/front/ticket.form.php", data=dados, timeout=20,
               allow_redirects=False)
    status = r.status_code
    location = r.headers.get("Location", "")

    debug = os.path.join(_BASE_DIR, "glpi_resposta.html")
    try:
        with open(debug, "w", encoding="utf-8") as f:
            f.write(f"STATUS: {status}\nLOCATION: {location}\n\n{r.text}")
    except Exception:
        pass

    log(f"GLPI POST -> HTTP {status} | Location: {location or '(nenhum)'}")

    if status in (301, 302, 303):
        m = re.search(r"id=(\d+)", location)
        if m:
            return m.group(1)   # chamado criado de verdade
        log(f"Redirecionou mas sem id no Location. Veja {debug}.")
        return None
    if status == 403:
        log(f"HTTP 403: GLPI recusou o POST (tipicamente token CSRF). "
            f"Chamado provavelmente NAO criado. Detalhes em {debug}.")
        return None
    log(f"Sem redirecionamento (HTTP {status}) - provavel campo obrigatorio faltando. "
        f"Detalhes em {debug}.")
    return None

def ler_planilha():
    """Busca os chamados no Web App do Apps Script (JSON) e devolve uma lista de
    dicts {coluna_minuscula: valor}. A primeira linha do JSON e o cabecalho.
    Levanta erro se falhar."""
    r = requests.get(WEBAPP_URL, timeout=30)
    if r.status_code != 200:
        raise RuntimeError(f"Web App respondeu HTTP {r.status_code}. Confira a WEBAPP_URL.")
    try:
        matriz = r.json()          # ex: [["ID","Título","Status",...],["86940",...],...]
    except ValueError:
        raise RuntimeError("O Web App nao devolveu JSON valido. Confira a implantacao "
                           "(deve terminar em /exec) e o 'Quem pode acessar'.")
    if not matriz or not matriz[0]:
        return []
    cabecalho = [str(c).strip().lower() for c in matriz[0]]
    for col in (COL_ID, COL_TITULO, COL_STATUS):
        if col.strip().lower() not in cabecalho:
            raise RuntimeError(f"Coluna '{col}' nao encontrada. Cabecalho: {matriz[0]}")
    registros = []
    for linha in matriz[1:]:
        registros.append({cabecalho[i]: (str(linha[i]) if i < len(linha) else "")
                          for i in range(len(cabecalho))})
    return registros


def _resolvidos():
    return {s.strip().lower() for s in STATUS_RESOLVIDOS.split(",")}


def _norm(texto):
    """Minusculo e sem acentos, para comparar titulos sem quebrar por 'memória' vs 'memoria'."""
    t = unicodedata.normalize("NFKD", texto)
    return "".join(c for c in t if not unicodedata.combining(c)).lower()


def status_do_chamado(registros, ticket_id):
    """Devolve o status (minusculo) do chamado com aquele ID, ou None se ainda
    nao estiver na planilha."""
    alvo = str(ticket_id).strip()
    col_id, col_status = COL_ID.lower(), COL_STATUS.lower()
    for reg in registros:
        if reg.get(col_id, "").strip() == alvo:
            return reg.get(col_status, "").strip().lower()
    return None


def existe_chamado_aberto(registros):
    """True se houver algum chamado DO SCRIPT (frase discreta em TITULO_KEYWORD)
    ainda nao resolvido. Nao considera chamados de lentidao abertos por humanos."""
    col_titulo, col_status = COL_TITULO.lower(), COL_STATUS.lower()
    resolvidos = _resolvidos()
    chave = _norm(TITULO_KEYWORD)
    for reg in registros:
        titulo = _norm(reg.get(col_titulo, ""))
        status = reg.get(col_status, "").strip().lower()
        if chave in titulo and status and status not in resolvidos:
            return True
    return False


def ler_estado():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def salvar_estado(dados):
    with open(STATE_FILE, "w") as f:
        json.dump(dados, f)


def em_guarda_tempo(iso):
    """Fallback: usado so quando abrimos um chamado mas nao capturamos o ID."""
    try:
        ultimo = datetime.datetime.fromisoformat(iso)
    except Exception:
        return False
    return (datetime.datetime.now() - ultimo).total_seconds() / 60 < COOLDOWN_MIN


def em_backoff(estado):
    """True se houve erro recente e ainda estamos no periodo de espera.
    A espera dobra a cada erro seguido (90 -> 180 -> 360 min, limitada pelo teto),
    para nao ficar martelando um servico que esta fora do ar."""
    n = estado.get("erros_seguidos", 0)
    if n <= 0 or not estado.get("ultimo_erro"):
        return False
    try:
        t = datetime.datetime.fromisoformat(estado["ultimo_erro"])
    except Exception:
        return False
    espera = min(ERRO_BACKOFF_BASE * (2 ** (n - 1)), ERRO_BACKOFF_MAX)
    minutos = (datetime.datetime.now() - t).total_seconds() / 60
    return minutos < espera


def main(estado):
    faltando = [n for n, v in {
        "ZABBIX_URL": ZBX_URL, "ZABBIX_USER": ZBX_USER, "ZABBIX_PASS": ZBX_PASS,
        "GLPI_URL": GLPI_URL, "GLPI_USER": GLPI_USER, "GLPI_PASS": GLPI_PASS,
        "WEBAPP_URL": WEBAPP_URL,
    }.items() if not v]
    if faltando:
        sys.exit("Faltam variaveis de ambiente: " + ", ".join(faltando))

    token = zbx_login()
    try:
        uso, nome = zbx_memoria(token)
    finally:
        zbx_logout(token)

    log(f"{nome}: {uso:.2f}% (limite {THRESHOLD:.0f}%)")

    if uso < THRESHOLD:
        log("Abaixo do limite. Nada a fazer.")
        return

    registros = ler_planilha()

    pendente = estado.get("pending_ticket_id")
    if pendente:
        st = status_do_chamado(registros, pendente)
        if st is None:
            log(f"Chamado #{pendente} que abri ainda nao apareceu na planilha "
                "(sync roda 8h/12h/17h). Aguardando. Nao abre outro.")
            return
        if st not in _resolvidos():
            log(f"Chamado #{pendente} ainda esta '{st}'. Nao abre outro.")
            return
        log(f"Chamado #{pendente} foi resolvido ('{st}'). Liberado para abrir novo se preciso.")
        estado["pending_ticket_id"] = None
    elif estado.get("opened_at") and em_guarda_tempo(estado["opened_at"]):
        # Abrimos algo mas nao capturamos o ID: usa guarda de tempo como fallback.
        log(f"Abri um chamado ha pouco (sem ID confirmado). Aguardando {COOLDOWN_MIN} min.")
        return

    if existe_chamado_aberto(registros):
        log("Ja existe chamado do monitor nao resolvido na planilha. Nao abre outro.")
        return

    log("Acima do limite e nenhum chamado do monitor em aberto. Abrindo chamado no GLPI...")
    s = glpi_login()
    ticket_id = glpi_abrir_chamado(
        s,
        titulo=f"Lentidao no sistema - memoria alta ({uso:.1f}%)",
        descricao=(f"Alerta automatico (Zabbix): {nome} em {uso:.2f}%, "
                   f"acima do limite de {THRESHOLD:.0f}%. "
                   f"Data/hora: {datetime.datetime.now():%d/%m/%Y %H:%M}."),
        urgencia=4,
    )
    if ticket_id:
        log(f"Chamado aberto com sucesso: #{ticket_id}")
        estado["pending_ticket_id"] = ticket_id
    else:
        log("Nao consegui confirmar o id do chamado. Verifique os campos do formulario "
            "(veja o comentario em glpi_abrir_chamado).")
        estado["pending_ticket_id"] = None
    estado["opened_at"] = datetime.datetime.now().isoformat()


if __name__ == "__main__":
    estado = ler_estado()

    if em_backoff(estado):
        log(f"Em backoff apos {estado.get('erros_seguidos')} erro(s). Pulando esta execucao.")
        sys.exit(0)

    try:
        main(estado)
        estado["erros_seguidos"] = 0
        estado.pop("ultimo_erro", None)
    except Exception as e:
        estado["erros_seguidos"] = estado.get("erros_seguidos", 0) + 1
        estado["ultimo_erro"] = datetime.datetime.now().isoformat()
        log(f"ERRO (falha #{estado['erros_seguidos']}): {e}. Nao vou insistir; espero antes de tentar de novo.")
    finally:
        salvar_estado(estado)
