# -*- coding: utf-8 -*-
"""
GOC - Revision Diaria Core MPLS/ISP v4
Fuentes:
  - Netbox API    -> inventario routers (IP, nombre, ciudad)
  - InfluxDB via Grafana -> TODO: estado actual + historico 24h
Polling cada 5 min en background.
alertas_rt.json   -> estado actual (persiste entre F5)
alertas_hist.json -> historial del dia
Correo HTML via MAT (manual)
"""
from flask import Flask, request, jsonify, send_file, session
from functools import wraps
import requests as req
import json, os, re as _re, threading, time, subprocess
from datetime import datetime, date
from collections import defaultdict
import warnings
warnings.filterwarnings("ignore")

app = Flask(__name__)
app.secret_key = "goc-trafico-core-2026"
app.config["PERMANENT_SESSION_LIFETIME"] = __import__("datetime").timedelta(days=7)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_NAME"] = "goc_session"

# ---------------------------------------------------------------------------
# RUTAS
# ---------------------------------------------------------------------------
DATA_DIR        = "/app/data"
CONFIG_FILE     = os.path.join(DATA_DIR, "config.json")
REVISIONES_FILE = os.path.join(DATA_DIR, "revisiones.json")
ACK_FILE        = os.path.join(DATA_DIR, "alarmas_ack.json")
ALERTAS_RT      = os.path.join(DATA_DIR, "alertas_rt.json")
ALERTAS_HIST    = os.path.join(DATA_DIR, "alertas_hist.json")
CACHE_FILE      = os.path.join(DATA_DIR, "cache_devices.json")

# ---------------------------------------------------------------------------
# CONFIG APIs
# ---------------------------------------------------------------------------
NETBOX_URL   = "http://10.68.12.247:8000"
NETBOX_TOKEN = "5b8570bb8485ddbc6bce50ab99c6904ee6ad9606"
GRAFANA_URL  = os.environ.get("GRAFANA_URL",  "https://clarochile.grafana.net")
GRAFANA_TOKEN= os.environ.get("GRAFANA_TOKEN","")
DS_UID       = os.environ.get("TRAFICO_DS_UID","bdgrcgfft4feoe")
MAT_URL      = "https://mat-vpto.clarochile.cl/mat/api/v2/networktask/lw9-etr-ptk/env/production/jobs"
MAT_APIKEY   = "wM4hBakKw2MKG0HactSKsCMZBAozVS14"

ROLES_NETBOX  = ["router-p", "router-pe"]
DESCRIPTORES  = ["BBUPLINK","BBPUPLINK","BBPREG","BBPUPLINKS"]
DESC_REGEX    = "BBUPLINK|BBPUPLINK|BBPREG|BBPUPLINKS"

SAT_PCT   = 80  # Umbral saturacion 80%
ERR_MIN   = 1.0
DIS_MIN   = 10
POLL_SECS = 300
MAX_BPS   = 10e12

USUARIOS_FILE  = os.path.join(DATA_DIR, "usuarios.json")
CORREOS_FILE   = os.path.join(DATA_DIR, "correos.json")

# USERS y DEST_CORREO se inicializan despues de definir save_json/load_json

_lock             = threading.Lock()
_polling_iniciado = False
_ultimo_poll      = None


# ---------------------------------------------------------------------------
# SYSLOG MODULE
# ---------------------------------------------------------------------------
SYSLOG_SSH_KEY  = "/root/.ssh/id_rsa_syslog"
SYSLOG_USER     = "cllanos"
SYSLOG_HOST     = "10.68.12.101"
SYSLOG_BASE     = "/syslog/2026"
SYSLOG_IP_MAP_FILE   = os.path.join(DATA_DIR, "syslog_ip_map.json")
SYSLOG_VENDOR_MAP_FILE = os.path.join(DATA_DIR, "syslog_vendor_map.json")
SYSLOG_SCOPE_FILE    = os.path.join(DATA_DIR, "syslog_scope.json")
SYSLOG_CACHE_FILE    = os.path.join(DATA_DIR, "syslog_cache.json")

# Patrones de eventos relevantes
SYSLOG_PATTERNS = [
    # BGP
    {"re": r"BGP.*ADJCHANGE.*neighbor.*?(Up|Down)", "tipo": "bgp", "sev": "critico"},
    {"re": r"BGP.*neighbor.*?(Up|Down|Reset|Idle|Active)", "tipo": "bgp", "sev": "critico"},
    {"re": r"01BGP.*PEER_STATE_CHG.*CurrState=(IDLE|ACTIVE|CONNECT)", "tipo": "bgp", "sev": "critico"},
    {"re": r"RPD_BGP_NEIGHBOR.*(Up|Down|Reset)", "tipo": "bgp", "sev": "critico"},
    {"re": r"bgp_recv.*(failed|EOF|error)", "tipo": "bgp", "sev": "importante"},
    {"re": r"bgp_listen_accept.*(Rejected|unconfigured)", "tipo": "bgp", "sev": "advertencia"},
    {"re": r"NOTIFICATION (sent|received).*(Cease|Hold Timer)", "tipo": "bgp", "sev": "importante"},
    # BGP EVPN / VXLAN
    {"re": r"BGP.*EVPN.*(Up|Down|error)", "tipo": "bgp_evpn", "sev": "critico"},
    {"re": r"NVE.*peer.*(Up|Down|add|remove)", "tipo": "vxlan", "sev": "critico"},
    {"re": r"VXLAN.*(Up|Down|error|fail)", "tipo": "vxlan", "sev": "critico"},
    {"re": r"VTEP.*(Up|Down|add|remove)", "tipo": "vxlan", "sev": "critico"},
    # ISIS
    {"re": r"ISIS.*adjacency.*(Up|Down|CHANGE|lost|new)", "tipo": "isis", "sev": "critico"},
    {"re": r"ISIS.*ADJ.*(Up|Down)", "tipo": "isis", "sev": "critico"},
    # OSPF
    {"re": r"OSPF.*neighbor.*(Up|Down|CHANGE|Dead|Full)", "tipo": "ospf", "sev": "importante"},
    {"re": r"01OSPF.*(neighbor|adjacency).*(Up|Down|change)", "tipo": "ospf", "sev": "importante"},
    # Interface IOS-XR
    {"re": r"PKT_INFRA-LINK.*UPDOWN.*Interface.*state to (Up|Down)", "tipo": "interface", "sev": "critico"},
    # Interface Huawei
    {"re": r"01IFNET.*interface.*(up|down)", "tipo": "interface", "sev": "critico"},
    # Interface Nexus
    {"re": r"IF_DOWN|IF_UP|ETH_PORT_CHANNEL_FOP|ETH_PORT_CHANNEL_FOC", "tipo": "interface", "sev": "critico"},
    # Interface Juniper
    {"re": r"SNMP_TRAP_LINK_(UP|DOWN)", "tipo": "interface", "sev": "critico"},
    # Bundle/LAG/LACP
    {"re": r"L2-BM.*(ACTIVE|DOWN|MBR).*(up|down|fail)", "tipo": "bundle", "sev": "critico"},
    {"re": r"01LACP.*(up|down|change|fail)", "tipo": "bundle", "sev": "critico"},
    {"re": r"01TRUNK.*(up|down|change)", "tipo": "bundle", "sev": "critico"},
    {"re": r"LACP.*(up|down|change|expired|fail)", "tipo": "bundle", "sev": "critico"},
    {"re": r"VPC.*(peer|keepalive|down|up|suspend)", "tipo": "bundle", "sev": "critico"},
    {"re": r"ETH_PORT_CHANNEL_FOP|ETH_PORT_CHANNEL_FOC", "tipo": "bundle", "sev": "critico"},
    # BFD
    {"re": r"L2-BFD.*(SESSION_STATE|REMOVED|DAMPENING)", "tipo": "bfd", "sev": "importante"},
    {"re": r"BFD.*(down|up|session|fail)", "tipo": "bfd", "sev": "importante"},
    # MPLS-TE
    {"re": r"RSVP.*tunnel.*(up|down|flap|fail)", "tipo": "mpls", "sev": "importante"},
    {"re": r"LDP.*session.*(up|down|fail)", "tipo": "mpls", "sev": "importante"},
    {"re": r"01TUNNEL-TE.*(up|down|fail|change)", "tipo": "mpls", "sev": "importante"},
    # L2VPN / AC
    {"re": r"(L2VPN|AC|pseudowire|PW).*(up|down|fail|change)", "tipo": "l2vpn", "sev": "importante"},
    {"re": r"01L3VPN.*(up|down|fail)", "tipo": "l2vpn", "sev": "importante"},
    # PIM Multicast
    {"re": r"IPV4_PIM.*NBRCHG.*(up|down|expire)", "tipo": "multicast", "sev": "importante"},
    # Hardware
    {"re": r"PLATFORM-VIC.*(RX_LOS|RFI|SIGNAL|fail)", "tipo": "hardware", "sev": "critico"},
    {"re": r"(FAN|PSU|POWER|TEMPERATURE).*(fail|alarm|critical|down|error)", "tipo": "hardware", "sev": "critico"},
    {"re": r"(linecard|line.card|module|slot).*(fail|down|removed|error|reset)", "tipo": "hardware", "sev": "critico"},
    {"re": r"(memory|mem).*(error|fail|exhausted|critical)", "tipo": "hardware", "sev": "critico"},
    {"re": r"OPTICAL.*(alarm|fail|error|loss)", "tipo": "hardware", "sev": "critico"},
    # Seguridad
    {"re": r"SSH_USER_LOGIN_FAIL.*time", "tipo": "seguridad", "sev": "advertencia"},
    {"re": r"login.*fail.*time", "tipo": "seguridad", "sev": "advertencia"},
]

SYSLOG_TIPO_LABEL = {
    "bgp":       "BGP",
    "bgp_evpn":  "BGP EVPN",
    "isis":      "ISIS",
    "ospf":      "OSPF",
    "interface": "Interface",
    "bundle":    "Bundle/LAG",
    "bfd":       "BFD",
    "mpls":      "MPLS/TE",
    "l2vpn":     "L2VPN/AC",
    "multicast": "Multicast",
    "vxlan":     "VXLAN",
    "hardware":  "Hardware",
    "seguridad": "Seguridad",
}


def syslog_resolver_nombre(host_field, ip):
    """Resuelve nombre del equipo desde el campo host o IP."""
    import re as _r
    mapa = load_json(SYSLOG_IP_MAP_FILE, {})
    # Si es una IP directa
    if _r.match(r"^\d+\.\d+\.\d+\.\d+$", host_field):
        return mapa.get(host_field, host_field)
    # Si es reverse DNS tipo pc-A-B-C-D.cm.vtr.net -> IP D.C.B.A
    m = _r.match(r"pc-(\d+)-(\d+)-(\d+)-(\d+)", host_field)
    if m:
        ip_from_rdns = f"{m.group(4)}.{m.group(3)}.{m.group(2)}.{m.group(1)}"
        if ip_from_rdns in mapa:
            return mapa[ip_from_rdns]
    # Si ya tiene nombre operacional (Juniper/Huawei), usarlo sin dominio
    nombre = host_field.split(".")[0]
    return nombre

def syslog_resolver_vendor(nombre, ip):
    """Resuelve el fabricante (CISCO/HUAWEI/JUNIPER/F5/FORTINET) por nombre o IP."""
    vmap = load_json(SYSLOG_VENDOR_MAP_FILE, {})
    por_nombre = vmap.get("por_nombre", {})
    por_ip = vmap.get("por_ip", {})
    if nombre in por_nombre:
        return por_nombre[nombre]
    if ip in por_ip:
        return por_ip[ip]
    return "OTRO"

def syslog_parsear_linea(linea):
    """Parsea una linea de syslog y retorna evento o None."""
    import re as _r
    # Extraer timestamp, host, msg
    m = _r.match(r"(\S+)\s+host:(\S+)\s+msg:\s*(.+?)(?:\s+tag:|$)", linea)
    if not m:
        return None
    ts_raw, host, msg = m.group(1), m.group(2), m.group(3)
    # Parsear timestamp
    try:
        ts = ts_raw[:19].replace("T", " ")
    except:
        ts = ts_raw
    # Resolver nombre
    import re as _r2
    ip_match = _r2.match(r"^(\d+\.\d+\.\d+\.\d+)$", host)
    ip = host if ip_match else ""
    nombre = syslog_resolver_nombre(host, ip)
    # Buscar patron relevante
    msg_upper = msg.upper()
    for pat in SYSLOG_PATTERNS:
        if _r2.search(pat["re"], msg, _r2.IGNORECASE):
            return {
                "ts":     ts,
                "equipo": nombre,
                "tipo":   pat["tipo"],
                "tipo_label": SYSLOG_TIPO_LABEL.get(pat["tipo"], pat["tipo"]),
                "sev":    pat["sev"],
                "msg":    msg[:200],
                "ip":     ip or host,
                "vendor": syslog_resolver_vendor(nombre, ip or host),
            }
    return None

def syslog_get_eventos(horas=4, max_eventos=500):
    """Lee eventos syslog relevantes via SSH con xargs paralelo."""
    scope = load_json(SYSLOG_SCOPE_FILE, {})
    ips = scope.get("ips", [])
    if not ips:
        return []

    keywords = "BGP|ISIS|OSPF|UPDOWN|ADJCHANGE|LDP|RSVP|LOGIN_FAIL|SSH_USER_LOGIN_FAIL|FAN|PSU|linecard|bundle|LACP|TRUNK|IFNET|TUNNEL-TE|L3VPN|SNMP_TRAP_LINK|VXLAN|VTEP|NVE|L2VPN|EVPN"
    tail_lines = max(100, horas * 60)

    # Construir lista de archivos
    archivos = "\n".join([f"/syslog/2026/{ip}/{ip}.log" for ip in ips])

    # Script remoto: xargs paralelo con tail+grep en cada archivo
    remote_cmd = (
        "echo '" + archivos + "' | "
        "xargs -P 30 -I{} sh -c "
        "'tail -" + str(tail_lines) + " {} 2>/dev/null | grep -iE \"" + keywords + "\" | tail -30'"
    )

    try:
        cmd = [
            "ssh", "-i", SYSLOG_SSH_KEY,
            "-o", "StrictHostKeyChecking=no",
            "-o", "ConnectTimeout=10",
            f"{SYSLOG_USER}@{SYSLOG_HOST}",
            remote_cmd
        ]
        out = subprocess.check_output(cmd, timeout=30, stderr=subprocess.DEVNULL).decode(errors="replace")
    except Exception as e:
        print(f"[Syslog] Error SSH: {e}")
        return []

    eventos = []
    for linea in out.strip().split("\n"):
        if not linea.strip():
            continue
        ev = syslog_parsear_linea(linea)
        if ev:
            eventos.append(ev)

    # Round-robin por equipo: garantiza representacion pareja sin importar
    # cuan ruidoso sea cada equipo (evita que uno tape a los demas por recencia)
    from collections import defaultdict as _dd
    por_equipo = _dd(list)
    for ev in eventos:
        por_equipo[ev["equipo"]].append(ev)
    for _eq in por_equipo:
        por_equipo[_eq].sort(key=lambda x: x["ts"], reverse=True)
    eventos_bal = []
    equipos_list = list(por_equipo.keys())
    idx = 0
    while len(eventos_bal) < max_eventos and any(por_equipo[eq] for eq in equipos_list):
        eq = equipos_list[idx % len(equipos_list)]
        if por_equipo[eq]:
            eventos_bal.append(por_equipo[eq].pop(0))
        idx += 1
    eventos_bal.sort(key=lambda x: x["ts"], reverse=True)
    return eventos_bal[:max_eventos]
# ---------------------------------------------------------------------------
# DECORADORES
# ---------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return jsonify({"error": "unauthorized"}), 401
        if USERS.get(session["user"], {}).get("role") != "admin":
            return jsonify({"error": "forbidden"}), 403
        return f(*args, **kwargs)
    return decorated

# ---------------------------------------------------------------------------
# PERSISTENCIA
# ---------------------------------------------------------------------------
def load_json(path, default=None):
    if default is None:
        default = {}
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    except Exception as e:
        print(f"[GOC] Error guardando {path}: {e}")

USERS_DEFAULT = {
    "admin":    {"password": "admin123",  "role": "admin",  "activo": True},
    "cllanos":  {"password": "Claro2027", "role": "admin",  "activo": True},
    "goc":      {"password": "goc2026",   "role": "viewer", "activo": True},
    "jefatura": {"password": "jefe2026",  "role": "viewer", "activo": True},
}
CORREOS_DEFAULT = [
    "Carlos.RamirezMarchant@clarovtr.cl",
    "carlos.vergara@clarovtr.cl",
    "claudio.llanos@clarovtr.cl",
    "juan.garrido@clarovtr.cl",
    "david.melita@clarovtr.cl",
    "cristian.trepiana@clarovtr.cl",
    "Victor.Montoya@nttdata.com"
]

def load_users():
    if not os.path.exists(USUARIOS_FILE):
        save_json(USUARIOS_FILE, USERS_DEFAULT)
    return load_json(USUARIOS_FILE, USERS_DEFAULT)

def save_users(u):
    save_json(USUARIOS_FILE, u)

def load_correos():
    if not os.path.exists(CORREOS_FILE):
        save_json(CORREOS_FILE, CORREOS_DEFAULT)
    return load_json(CORREOS_FILE, CORREOS_DEFAULT)

def save_correos(c):
    save_json(CORREOS_FILE, c)

# Inicializar usuarios y correos (requiere save_json y load_json)
USERS = load_users()
DEST_CORREO = load_correos()

def load_config():
    return load_json(CONFIG_FILE, {
        "umbrales":      {"saturacion_pct": 90},
        "secciones":     [],
        "turnos":        ["AM","PM","NOC"],
        "usuarios_turno":["Claudio Llanos","Carlos Vergara","Carlos Ramirez",
                          "David Melita","Juan Garrido","Victor Montoya"],
        "grupos":        {}
    })

def load_ack():    return load_json(ACK_FILE, [])
def save_ack(a):   save_json(ACK_FILE, a)
def load_revisiones():   return load_json(REVISIONES_FILE, [])
def save_revisiones(r):  save_json(REVISIONES_FILE, r)

def load_alertas_rt():
    return load_json(ALERTAS_RT, {
        "ts": None, "alarmas": [], "routers": [],
        "resumen": {"total":0,"en_alerta":0,"saturaciones":0,"caidas":0,
                    "cap_perdidas":0,"conmutaciones":0,"errores":0,"normales":0}
    })

def load_hist():
    h   = load_json(ALERTAS_HIST, {"fecha": None, "eventos": []})
    hoy = date.today().strftime("%d/%m/%Y")
    if h.get("fecha") != hoy:
        h = {"fecha": hoy, "eventos": []}
        save_json(ALERTAS_HIST, h)
    return h


ARCHIVO_HIST = os.path.join(DATA_DIR, "alertas_archivo.json")

def mover_a_archivo():
    """Mueve alarmas resueltas con mas de 24h al archivo historico permanente."""
    from datetime import datetime, timedelta
    h = load_hist()
    eventos = h.get("eventos", [])
    limite = datetime.now() - timedelta(hours=24)
    quedan = []
    mover = []
    for ev in eventos:
        if ev.get("ts_fin"):
            try:
                ts = datetime.strptime(ev["ts_fin"][:16], "%d/%m/%Y %H:%M")
                if ts < limite:
                    mover.append(ev)
                else:
                    quedan.append(ev)
            except:
                quedan.append(ev)
        else:
            quedan.append(ev)
    if mover:
        # Cargar archivo historico
        try:
            archivo = load_json(ARCHIVO_HIST, {"eventos": []})
        except:
            archivo = {"eventos": []}
        archivo["eventos"].extend(mover)
        save_json(ARCHIVO_HIST, archivo)
        h["eventos"] = quedan
        save_hist(h)
        print("[Archivo] Movidos", len(mover), "eventos al archivo historico")

def actualizar_hist(alarmas_actuales):
    h     = load_hist()
    ahora = datetime.now().strftime("%d/%m/%Y %H:%M")
    ahora_dt = datetime.now()
    # Ventana de gracia: si desaparece y vuelve en menos de 15 min = misma alarma
    GRACIA_MIN = 15
    keys_actuales = {(a["router"],a["tipo"],a.get("ifname",""))
                     for a in alarmas_actuales if a.get("activa",True)}
    for ev in h["eventos"]:
        key = (ev["router"],ev["tipo"],ev.get("ifname",""))
        if key not in keys_actuales and not ev.get("ts_fin"):
            # Antes de resolver, verificar si es una alarma persistente (caida_bundle/equipos_down)
            # Esas solo se resuelven cuando Grafana las reporta como OK explicitamente
            if ev.get("tipo") in ("caida_bundle","equipos_down","miembro_down","alerta","saturacion","recurso","errores","descartes","drp"):
                # No resolver automaticamente - esperar confirmacion
                continue
            ev["ts_fin"]   = ahora
            ev["activa"]   = False
            ev["duracion"] = _dur(ev["ts_inicio"], ahora)
    # Eventos activos en historial (sin ts_fin)
    eventos_activos = {(ev["router"],ev["tipo"],ev.get("ifname","")): ev
                       for ev in h["eventos"] if not ev.get("ts_fin")}
    # Eventos recientemente resueltos (dentro de ventana de gracia)
    eventos_gracia = {}
    for ev in h["eventos"]:
        if ev.get("ts_fin"):
            try:
                ts_fin_dt = datetime.strptime(ev["ts_fin"], "%d/%m/%Y %H:%M")
                diff_min = (ahora_dt - ts_fin_dt).total_seconds() / 60
                if diff_min <= GRACIA_MIN:
                    key = (ev["router"],ev["tipo"],ev.get("ifname",""))
                    eventos_gracia[key] = ev
            except:
                pass
    for a in alarmas_actuales:
        if not a.get("activa",True):
            continue
        key = (a["router"],a["tipo"],a.get("ifname",""))
        if key in eventos_activos:
            # Ya existe activa - no duplicar
            continue
        if key in eventos_gracia:
            # Volvio dentro de la ventana de gracia - reactivar la misma entrada
            ev = eventos_gracia[key]
            ev["ts_fin"]   = None
            ev["activa"]   = True
            ev["duracion"] = None
            continue
        # Nueva alarma
        print("[HIST] Nueva alarma:", a.get("router"), a.get("tipo"), a.get("ifname",""), flush=True)
        h["eventos"].append({
            "router":        a.get("router",""),
            "tipo":          a.get("tipo",""),
            "sev":           a.get("sev",""),
            "ifname":        a.get("ifname",""),
            "desc":          a.get("desc",""),
            "valor":         a.get("valor",""),
            "ts_inicio":     ahora,
            "ts_fin":        None,
            "duracion":      None,
            "activa":        True,
            "fuente":        a.get("fuente","influx"),
            "categoria":     a.get("categoria",""),
            "descriptor":    a.get("descriptor",""),
            "grafana_panel": a.get("grafana_panel",""),
        })
    save_json(ALERTAS_HIST, h)

def _dur(ini, fin):
    try:
        fmt  = "%d/%m/%Y %H:%M"
        mins = int((datetime.strptime(fin,fmt)-datetime.strptime(ini,fmt)).total_seconds()/60)
        return f"{mins//60}h {mins%60}min" if mins>=60 else f"{mins} min"
    except Exception:
        return ""

def ahora_str():
    return datetime.now().strftime("%d/%m/%Y %H:%M")

# ---------------------------------------------------------------------------
# INVENTARIO — carga desde JSON estatico
# ---------------------------------------------------------------------------
ROUTERS_JSON = "/app/data/routers.json"

def cargar_inventario():
    """Carga el inventario de routers desde el JSON estatico."""
    data = load_json(ROUTERS_JSON, {"routers": []})
    routers = data.get("routers", [])
    print(f"[Inventario] {len(routers)} routers cargados desde JSON")
    return routers

# ---------------------------------------------------------------------------
# INFLUXDB via Grafana
# ---------------------------------------------------------------------------
def influx_query(q, timeout=30):
    url     = f"{GRAFANA_URL}/api/datasources/proxy/uid/{DS_UID}/query"
    params  = {"db":"trafico","epoch":"ms","q":q}
    headers = {"Authorization": f"Bearer {GRAFANA_TOKEN}"}
    try:
        r = req.get(url, params=params, headers=headers, timeout=timeout, verify=False)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

def influx_get_devname(ip):
    """Obtiene devname desde InfluxDB usando agent_host=IP."""
    q    = (f'SHOW TAG VALUES FROM "trafico" WITH KEY="devname" '
            f'WHERE "agent_host"=\'{ip}\' AND time > now()-1h')
    data = influx_query(q, timeout=10)
    vals = (data.get("results",[{}])[0]
                .get("series",[{}])[0]
                .get("values",[]))
    return vals[0][1] if vals else None

def influx_get_interfaces_actual(devname, descriptores=None):
    """
    Estado ACTUAL de interfaces con descriptores de interes.
    Usa non_negative_derivative para errores/s reales.
    """
    desc_regex = "|".join(descriptores) if descriptores else DESC_REGEX
    q = (f'SELECT last("ifHCInOctets") AS in_bytes,'
         f' last("ifHCOutOctets") AS out_bytes,'
         f' last("ifSpeed") AS speed,'
         f' last("ifOper") AS oper,'
         f' non_negative_derivative(last("ifInErr"),1s) AS inerr,'
         f' non_negative_derivative(last("ifOutErr"),1s) AS outerr,'
         f' non_negative_derivative(last("ifInDiscards"),1s) AS indis,'
         f' non_negative_derivative(last("ifOutDiscards"),1s) AS outdis'
         f' FROM "trafico"'
         f' WHERE "devname"=\'{devname}\''
         f' AND "ifAlias"=~/({desc_regex})/'
         f' AND time > now()-30m'
         f' GROUP BY "ifName","devif","ifAlias"')
    data   = influx_query(q, timeout=15)
    series = data.get("results",[{}])[0].get("series",[])
    result = []
    for s in series:
        v = s.get("values",[None])[0]
        if not v:
            continue
        result.append({
            "ifname":  s["tags"]["ifName"],
            "devif":   s["tags"]["devif"],
            "alias":   s["tags"].get("ifAlias",""),
            "in_bytes":v[1] or 0,
            "out_bytes":v[2] or 0,
            "speed":   v[3] or 0,
            "oper":    int(v[4]) if v[4] is not None else 1,
            "inerr":   v[5] or 0,
            "outerr":  v[6] or 0,
            "indis":   v[7] or 0,
            "outdis":  v[8] or 0,
        })
    return result

def influx_get_historico_24h(devname, descriptores=None):
    """
    Historico 24h de interfaces con descriptores especificos del router.
    """
    desc_regex = "|".join(descriptores) if descriptores else DESC_REGEX
    q = (f'SELECT non_negative_derivative(mean("ifHCInOctets"),1s)*8 AS in_bps,'
         f' non_negative_derivative(mean("ifHCOutOctets"),1s)*8 AS out_bps,'
         f' mean("ifSpeed") AS speed,'
         f' min("ifOper") AS oper_min'
         f' FROM "trafico"'
         f' WHERE "devname"=\'{devname}\''
         f' AND "ifAlias"=~/({desc_regex})/'
         f' AND time > now()-24h'
         f' GROUP BY time(5m),"ifName","devif" fill(null)')
    data   = influx_query(q, timeout=30)
    series = data.get("results",[{}])[0].get("series",[])
    result = {}
    for s in series:
        ifname = s["tags"]["ifName"]
        devif  = s["tags"]["devif"]
        pts    = []
        for v in s.get("values",[]):
            if v[1] is None and v[2] is None:
                continue
            in_bps  = v[1] if v[1] and 0 < v[1] < MAX_BPS else 0
            out_bps = v[2] if v[2] and 0 < v[2] < MAX_BPS else 0
            pts.append({
                "ts":      v[0],
                "in_bps":  in_bps,
                "out_bps": out_bps,
                "speed":   v[3] or 0,
                "oper_min":int(v[4]) if v[4] is not None else 1,
                "inerr":   v[5] or 0,
                "outerr":  v[6] or 0,
                "indis":   v[7] or 0,
                "outdis":  v[8] or 0,
            })
        if pts:
            result[ifname] = {"devif": devif, "pts": pts}
    return result

def influx_get_router_data(devname, descriptores=None):
    """
    Query combinada: estado actual + historico 2h para deteccion de eventos.
    Una sola llamada a Grafana por router para maxima eficiencia.
    """
    desc_regex = "|".join(descriptores) if descriptores else DESC_REGEX

    # Query 1: estado actual (ultimos 30 min)
    # Nota: non_negative_derivative no funciona con last() en InfluxDB
    # Los errores los calculamos comparando el ultimo valor con el anterior
    q_actual = (f'SELECT last("ifHCInOctets") AS in_bytes,'
                f' last("ifHCOutOctets") AS out_bytes,'
                f' last("ifSpeed") AS speed,'
                f' last("ifOper") AS oper,'
                f' last("ifInErr") AS inerr_raw,'
                f' last("ifOutErr") AS outerr_raw,'
                f' last("ifInDiscards") AS indis_raw,'
                f' last("ifOutDiscards") AS outdis_raw'
                f' FROM "trafico"'
                f' WHERE "devname"=\'{devname}\''
                f' AND "ifAlias"=~/({desc_regex})/'
                f' AND time > now()-30m'
                f' GROUP BY "ifName","devif","ifAlias"')

    # Query 2: historico 2h para detectar caidas recientes
    # Usamos 2h en vez de 24h para ser mucho mas rapidos
    q_hist = (f'SELECT non_negative_derivative(mean("ifHCInOctets"),1s)*8 AS in_bps,'
              f' non_negative_derivative(mean("ifHCOutOctets"),1s)*8 AS out_bps,'
              f' mean("ifSpeed") AS speed,'
              f' min("ifOper") AS oper_min,'
              f' non_negative_derivative(mean("ifInErr"),1s) AS inerr,'
              f' non_negative_derivative(mean("ifOutErr"),1s) AS outerr,'
              f' non_negative_derivative(mean("ifInDiscards"),1s) AS indis,'
              f' non_negative_derivative(mean("ifOutDiscards"),1s) AS outdis'
              f' FROM "trafico"'
              f' WHERE "devname"=\'{devname}\''
              f' AND "ifAlias"=~/({desc_regex})/'
              f' AND time > now()-2h'
              f' GROUP BY time(5m),"ifName","devif" fill(null)')

    # Ejecutar ambas queries en paralelo con ; (batch query)
    q_batch = f"{q_actual};{q_hist}"
    data = influx_query(q_batch, timeout=20)
    results = data.get("results", [{}, {}])

    # Parsear resultado actual
    ifaces_actual = []
    for s in results[0].get("series", []):
        v = s.get("values", [None])[0]
        if not v:
            continue
        ifaces_actual.append({
            "ifname":   s["tags"]["ifName"],
            "devif":    s["tags"]["devif"],
            "alias":    s["tags"].get("ifAlias",""),
            "in_bytes": v[1] or 0,
            "out_bytes":v[2] or 0,
            "speed":    v[3] or 0,
            "oper":     int(v[4]) if v[4] is not None else 1,
            "inerr":    0,   # se calcula desde historico
            "outerr":   0,   # se calcula desde historico
            "indis":    0,   # se calcula desde historico
            "outdis":   0,   # se calcula desde historico
        })

    # Parsear historico
    historico = {}
    for s in results[1].get("series", []):
        ifname = s["tags"]["ifName"]
        devif  = s["tags"]["devif"]
        pts = []
        for v in s.get("values", []):
            if v[1] is None and v[2] is None:
                continue
            in_bps  = v[1] if v[1] and 0 < v[1] < MAX_BPS else 0
            out_bps = v[2] if v[2] and 0 < v[2] < MAX_BPS else 0
            pts.append({
                "ts":      v[0],
                "in_bps":  in_bps,
                "out_bps": out_bps,
                "speed":   v[3] or 0,
                "oper_min":int(v[4]) if v[4] is not None else 1,
            })
        if pts:
            # Calcular errores/s del ultimo punto valido
            pts_err = [p for p in pts if p.get("inerr",0) > 0 or p.get("outerr",0) > 0]
            last_err = pts_err[-1] if pts_err else {}
            historico[ifname] = {
                "devif":  devif,
                "pts":    pts,
                "inerr":  last_err.get("inerr", 0),
                "outerr": last_err.get("outerr", 0),
                "indis":  last_err.get("indis", 0),
                "outdis": last_err.get("outdis", 0),
            }

    return ifaces_actual, historico

def influx_get_historico_devif(devif, ifname, ventana="24h"):
    """Historico de trafico para grafico de un devif especifico."""
    q = (f'SELECT non_negative_derivative(mean("ifHCInOctets"),1s)*8 AS in_bps,'
         f' non_negative_derivative(mean("ifHCOutOctets"),1s)*8 AS out_bps,'
         f' mean("ifSpeed") AS speed'
         f' FROM "trafico"'
         f' WHERE "devif"=\'{devif}\''
         f' AND time > now()-{ventana}'
         f' GROUP BY time(5m) fill(null)')
    data   = influx_query(q, timeout=30)
    series = data.get("results",[{}])[0].get("series",[])
    if not series:
        return []
    pts = []
    for v in series[0].get("values",[]):
        in_bps  = v[1] if v[1] and 0 < v[1] < MAX_BPS else 0
        out_bps = v[2] if v[2] and 0 < v[2] < MAX_BPS else 0
        if in_bps > 0 or out_bps > 0:
            pts.append({
                "ts":      v[0],
                "in_gbps": round(in_bps/1e9, 2),
                "out_gbps":round(out_bps/1e9,2),
                "speed_gbps": round((v[3] or 0)*1e6/1e9,1) if v[3] else 0,
            })
    return pts

# ---------------------------------------------------------------------------
# CACHE DE DISPOSITIVOS
# ---------------------------------------------------------------------------
def actualizar_cache():
    """
    Carga inventario desde JSON estatico.
    El devname ya viene definido en el JSON — no necesita cruce con APIs.
    """
    print("[Cache] Cargando desde inventario JSON...")
    routers = cargar_inventario()
    save_json(CACHE_FILE, {
        "ts":      ahora_str(),
        "routers": routers,
    })
    print(f"[Cache] {len(routers)} routers guardados en cache")
    return routers

def get_cache():
    c = load_json(CACHE_FILE, {})
    if not c.get("routers"):
        return []
    try:
        ts  = datetime.strptime(c["ts"], "%d/%m/%Y %H:%M")
        if (datetime.now()-ts).total_seconds() < 3600:
            return c["routers"]
    except Exception:
        pass
    return c.get("routers",[])

# ---------------------------------------------------------------------------
# UTILIDADES
# ---------------------------------------------------------------------------
def extraer_descriptor(alias):
    """Extrae solo el descriptor principal del ifAlias."""
    for d in ["BBPUPLINKS","BBPUPLINK","BBPREG","BBUPLINK"]:
        if d in alias:
            return d
    return alias[:30]

def es_fisica(ifname):
    return any(ifname.startswith(p) for p in
               ["TenGigE","HundredGigE","FortyGigE","GigabitEthernet",
                "TwentyFiveGigE","Ethernet","eth","xe-","ge-","et-",
                "100GE","10GE","40GE","Eth-Trunk","ae","Te1","Te0"])

def es_logica_principal(ifname):
    if "." in ifname:
        return False
    return any(ifname.startswith(p) for p in
               ["Bundle-Ether","ae","Eth-Trunk","port-channel","Po"])

def fmt_ts_influx(ts_ms):
    """Convierte timestamp ms a string legible."""
    try:
        if isinstance(ts_ms, str):
            dt = datetime.fromisoformat(ts_ms.replace("Z","+00:00"))
            # Convertir a hora local Chile (UTC-4)
            from datetime import timezone, timedelta
            chile = timezone(timedelta(hours=-4))
            dt    = dt.astimezone(chile)
            return dt.strftime("%d/%m %H:%M")
        dt = datetime.fromtimestamp(ts_ms/1000)
        return dt.strftime("%d/%m %H:%M")
    except Exception:
        return str(ts_ms)

# ---------------------------------------------------------------------------
# ANALISIS DE UN ROUTER
# ---------------------------------------------------------------------------
def analizar_router(router, interfaces_actual, historico_24h):
    """
    Analiza interfaces de un router.
    interfaces_actual: estado actual desde InfluxDB (ultimos 15 min)
    historico_24h: serie de puntos 24h por ifname
    """
    nombre = router.get("name","")
    ciudad = router.get("ciudad","")
    label  = f"{nombre} ({ciudad})" if ciudad else nombre
    ahora  = ahora_str()
    hoy    = date.today()
    anomalias = []

    for iface in interfaces_actual:
        ifname = iface["ifname"]
        alias  = iface["alias"]
        desc   = extraer_descriptor(alias)  # BBUPLINK, BBPREG, etc
        oper   = iface["oper"]
        speed  = iface.get("speed", 0) or 0
        hist   = historico_24h.get(ifname, {})
        # Errores vienen del historico (derivative correcto)
        inerr  = hist.get("inerr",  0) or 0
        outerr = hist.get("outerr", 0) or 0
        indis  = hist.get("indis",  0) or 0
        outdis = hist.get("outdis", 0) or 0
        pts    = hist.get("pts", [])
        devif  = hist.get("devif", iface.get("devif",""))

        # Calcular tráfico actual (ultimo punto valido del historico)
        pts_validos = [p for p in pts if p["in_bps"] > 0 or p["out_bps"] > 0]
        in_bps_now  = pts_validos[-1]["in_bps"]  if pts_validos else 0
        out_bps_now = pts_validos[-1]["out_bps"] if pts_validos else 0
        in_gbps     = round(in_bps_now/1e9, 2)
        out_gbps    = round(out_bps_now/1e9, 2)

        # Capacidad actual en Gbps (speed viene en Mbps en InfluxDB)
        cap_gbps = round(speed / 1000, 1) if speed and speed > 0 else 0

        # ---- INTERFACES LOGICAS (bundles principales) ----
        if es_logica_principal(ifname):

            # 1. CAIDA TOTAL DEL BUNDLE
            # Deshabilitado: Grafana detecta estas caidas via "Enlaces logicos en estado down"
            if False and oper == 2:
                pass

            # 2. SATURACION
            # Capacidad = suma ifSpeed fisicas up (Mbps)
            # Trafico = suma in_bytes de fisicas up convertido a bps
            elif es_logica_principal(ifname):
                fisicas_up = [f for f in interfaces_actual
                              if not es_logica_principal(f["ifname"])
                              and f["oper"] == 1
                              and f.get("speed", 0) > 0]
                if fisicas_up:
                    cap_mbps  = sum(f["speed"] for f in fisicas_up)
                    cap_gbps  = round(cap_mbps / 1000, 1)
                    # Trafico actual del bundle logico (in_bps_now ya viene en bps)
                    traf_in_gbps  = round(in_bps_now  / 1e9, 2)
                    traf_out_gbps = round(out_bps_now / 1e9, 2)
                    if cap_gbps > 0:
                        pct_in  = round(traf_in_gbps  / cap_gbps * 100, 1)
                        pct_out = round(traf_out_gbps / cap_gbps * 100, 1)
                        if pct_in >= SAT_PCT:
                            anomalias.append({
                                "tipo":      "saturacion",
                                "sev":       "critica",
                                "router":    label,
                                "ifname":    ifname,
                                "devif":     devif,
                                "desc":      (f"Saturacion en {ifname}: {pct_in}% "
                                              f"({traf_in_gbps}/{cap_gbps} Gbps, "
                                              f"{len(fisicas_up)} miembros up). [{desc}]"),
                                "valor":     f"{pct_in}% cap.",
                                "detectado": ahora,
                                "activa":    True,
                                "fecha":     date.today().strftime("%d/%m/%Y"),
                            })
                        if pct_out >= SAT_PCT:
                            anomalias.append({
                                "tipo":      "saturacion",
                                "sev":       "critica",
                                "router":    label,
                                "ifname":    ifname,
                                "devif":     devif,
                                "desc":      (f"Saturacion salida en {ifname}: {pct_out}% "
                                              f"({traf_out_gbps}/{cap_gbps} Gbps, "
                                              f"{len(fisicas_up)} miembros up). [{desc}]"),
                                "valor":     f"{pct_out}% cap. (out)",
                                "detectado": ahora,
                                "activa":    True,
                                "fecha":     date.today().strftime("%d/%m/%Y"),
                            })

            # 3. PERDIDA DE CAPACIDAD
            # Solo para interfaces logicas (bundle/ae/eth-trunk)
            # Capacidad = suma de ifSpeed de todos los miembros fisicos (Mbps / 1000 = Gbps)
            if pts and es_logica_principal(ifname):
                fisicas_all  = [f for f in interfaces_actual if not es_logica_principal(f["ifname"])]
                fisicas_up   = [f for f in fisicas_all if f["oper"]==1 and f.get("speed",0)>0]
                fisicas_tot  = [f for f in fisicas_all if f.get("speed",0)>0]
                cap_max_mbps = sum(f["speed"] for f in fisicas_tot)   # todos los miembros
                cap_now_mbps = sum(f["speed"] for f in fisicas_up)    # solo los up
                if cap_max_mbps > 0 and cap_now_mbps < cap_max_mbps * 0.9:
                    cap_max_gbps = int(round(cap_max_mbps / 1000, 0))
                    cap_now_gbps = int(round(cap_now_mbps / 1000, 0))
                    # Encontrar cuando bajo usando el historico
                    ts_cambio = ahora
                    for p in pts:
                        if p.get("oper_min",1) == 2:
                            ts_cambio = fmt_ts_influx(p["ts"])
                            break
                    ya = any(a["tipo"]=="cap_perdida" and ifname in a.get("ifname","")
                             for a in anomalias)
                    if not ya:
                        anomalias.append({
                            "tipo":      "cap_perdida",
                            "sev":       "importante",
                            "router":    label,
                            "ifname":    ifname,
                            "devif":     devif,
                            "desc":      (f"Capacidad reducida en {ifname}: "
                                          f"bajo de {cap_max_gbps} Gbps a {cap_now_gbps} Gbps "
                                          f"a las {ts_cambio}. [{desc}]"),
                            "valor":     f"{cap_now_gbps}/{cap_max_gbps} Gbps",
                            "detectado": ahora,
                            "activa":    True,
                            "fecha":     date.today().strftime("%d/%m/%Y"),
                        })

        # ---- INTERFACES FISICAS (miembros del bundle) ----
        elif es_fisica(ifname):

            # 4. MIEMBRO DOWN
            # Deshabilitado: Grafana detecta estas caidas via "Enlaces fisicos en estado down"
            if False and oper == 2:
                pass

            # 5. ERRORES
            # Errores: cualquier aumento del contador es alerta
            # non_negative_derivative > 0 significa que el contador aumentó
            total_err = inerr + outerr
            if total_err > 0.001:  # contador aumentando
                sev = "importante" if total_err > 100 else "advertencia"
                anomalias.append({
                    "tipo":      "errores",
                    "sev":       sev,
                    "router":    label,
                    "ifname":    ifname,
                    "devif":     devif,
                    "desc":      (f"Errores en {ifname}: {round(inerr,2)} in / "
                                  f"{round(outerr,2)} out err/s. [{desc}]"),
                    "valor":     f"{round(total_err,2)} err/s",
                    "detectado": ahora,
                    "activa":    True,
                    "fecha":     date.today().strftime("%d/%m/%Y"),
                })

            # 6. DESCARTES
            total_dis = indis + outdis
            if total_dis >= DIS_MIN:
                anomalias.append({
                    "tipo":      "descartes",
                    "sev":       "advertencia",
                    "router":    label,
                    "ifname":    ifname,
                    "devif":     devif,
                    "desc":      f"Descartes en {ifname}: {round(indis,1)} in / {round(outdis,1)} out desc/s. [{desc}]",
                    "valor":     f"{round(total_dis,1)} desc/s",
                    "detectado": ahora,
                    "activa":    True,
                    "fecha":     date.today().strftime("%d/%m/%Y"),
                })

    return anomalias

# ---------------------------------------------------------------------------
# DETECCION DE CONMUTACIONES
# ---------------------------------------------------------------------------
def generar_pares(routers_data):
    by_key = defaultdict(list)
    for r in routers_data:
        m = _re.match(r'^(.*?)(\d+)(-.*)?$', r["nombre"])
        if not m:
            continue
        key = f"{r['ciudad']}|{m.group(1)}{m.group(3) or ''}"
        by_key[key].append((int(m.group(2)), r))
    pares = []
    for items in by_key.values():
        if len(items) < 2:
            continue
        items.sort(key=lambda x: x[0])
        for i in range(0, len(items)-1, 2):
            pares.append([items[i][1], items[i+1][1]])
    return pares

# Cooldown en horas para conmutaciones sin causa
CONM_COOLDOWN_H = 4

def detectar_conmutaciones(pares, anomalias):
    nuevas = []
    ahora  = ahora_str()
    now_dt = datetime.now()

    # Cargar historial para verificar cooldown
    hist = load_hist()
    hist_conm = [ev for ev in hist.get("eventos",[]) if ev["tipo"] == "conmutacion"]

    for par in pares:
        r1, r2 = par[0], par[1]
        log1 = r1.get("logica_principal")
        log2 = r2.get("logica_principal")
        if not log1 or not log2:
            continue

        in1 = log1.get("in_bps_now", 0)
        in2 = log2.get("in_bps_now", 0)
        hist1 = log1.get("hist_bps_max", 0)  # maximo historico 2h
        hist2 = log2.get("hist_bps_max", 0)

        # Conmutacion real: uno cae a <10% de su historico y el otro sube
        # Esto detecta tanto caidas por OSPF como por capacidad
        # Evita falsas alarmas por trafico naturalmente asimetrico (PMON 83%/17%)
        if hist1 <= 0 and hist2 <= 0:
            continue

        caida1 = hist1 > 1e9 and in1 < hist1 * 0.10  # R1 cayo a <10% de su max
        caida2 = hist2 > 1e9 and in2 < hist2 * 0.10  # R2 cayo a <10% de su max

        if not caida1 and not caida2:
            continue  # Ninguno cayo - no es conmutacion

        # El que cayo es el origen, el que subio es el destino
        if caida1:
            origen, destino = r1["nombre"], r2["nombre"]
            if1n, if2n = log1.get("ifname",""), log2.get("ifname","")
            lab1 = f"{r1['nombre']} ({r1['ciudad']})" if r1.get("ciudad") else r1["nombre"]
            lab2 = f"{r2['nombre']} ({r2['ciudad']})" if r2.get("ciudad") else r2["nombre"]
            pct1 = round(in1/hist1*100) if hist1 > 0 else 0
            pct2 = round(in2/hist2*100) if hist2 > 0 else 100
        else:
            origen, destino = r2["nombre"], r1["nombre"]
            if1n, if2n = log2.get("ifname",""), log1.get("ifname","")
            lab1 = f"{r2['nombre']} ({r2['ciudad']})" if r2.get("ciudad") else r2["nombre"]
            lab2 = f"{r1['nombre']} ({r1['ciudad']})" if r1.get("ciudad") else r1["nombre"]
            pct1 = round(in2/hist2*100) if hist2 > 0 else 0
            pct2 = round(in1/hist1*100) if hist1 > 0 else 100

        ya = any(a["tipo"]=="conmutacion" and origen in a["desc"]
                 for a in anomalias+nuevas)
        if ya:
            continue

        # Buscar causa (link down, miembro down, cap_perdida)
        causa = ""
        for a in anomalias:
            if a["tipo"] in ("caida_bundle","miembro_down","cap_perdida") and origen in a["router"]:
                causa = f" CAUSA: {a['desc'][:80]}"
                break

        # Sin causa -> cooldown de 4h
        if not causa:
            r1n = r1["nombre"].split(" ")[0]
            r2n = r2["nombre"].split(" ")[0]
            ultima = None
            for ev in reversed(hist_conm):
                ev_router = ev["router"]
                if r1n in ev_router and r2n in ev_router:
                    try:
                        ultima = datetime.strptime(ev["ts_inicio"], "%d/%m/%Y %H:%M")
                    except Exception:
                        pass
                    break
            if ultima and (now_dt - ultima).total_seconds() < CONM_COOLDOWN_H * 3600:
                continue

        nuevas.append({
            "tipo":      "conmutacion",
            "sev":       "importante" if causa else "info",
            "router":    f"{origen} -> {destino}",
            "ifname":    f"{if1n}/{if2n}",
            "devif":     "",
            "desc":      (f"Posible conmutacion: {lab1} [{if1n}] cayo a {pct1}% de su trafico normal, "
                          f"{lab2} [{if2n}] al {pct2}%. "
                          f"Verificar si fue planificada.{causa}"),
            "valor":     "Conmutacion",
            "detectado": ahora,
            "activa":    not bool(causa),
            "fecha":     date.today().strftime("%d/%m/%Y"),
        })
    return nuevas

# ---------------------------------------------------------------------------
# CICLO DE POLLING
# ---------------------------------------------------------------------------
def ejecutar_polling():
    global _ultimo_poll
    print(f"[GOC Poll] Iniciando {ahora_str()}")

    routers = get_cache()
    if not routers:
        print("[GOC Poll] Cache vacio, actualizando...")
        routers = actualizar_cache()
    if not routers:
        print("[GOC Poll] Sin routers, abortando")
        return

    todas_anomalias    = []
    routers_con_ifaces = []
    consultados        = 0

    for router in routers:
        devname = router.get("devname")
        if not devname:
            continue

        descriptores = router.get("descriptores", DESCRIPTORES)
        try:
            # Una sola query combinada: estado actual + mini historico
            ifaces_actual, historico = influx_get_router_data(devname, descriptores)
            if not ifaces_actual:
                continue
            consultados += 1
        except Exception as e:
            continue

        # Interfaz logica principal (mayor trafico)
        logicas = [i for i in ifaces_actual if es_logica_principal(i["ifname"])]
        logica_principal = None
        if logicas:
            pts_dict = {ifn: historico.get(ifn,{}).get("pts",[]) for ifn in [l["ifname"] for l in logicas]}
            for l in logicas:
                pts = pts_dict.get(l["ifname"],[])
                pts_v = [p for p in pts if p["in_bps"]>0]
                l["in_bps_now"] = pts_v[-1]["in_bps"] if pts_v else 0
            logica_principal = max(logicas, key=lambda l: l.get("in_bps_now",0))
            # Agregar maximo historico y out_bps_now para deteccion de conmutacion
            if logica_principal:
                lp_ifname = logica_principal["ifname"]
                lp_pts = pts_dict.get(lp_ifname, [])
                lp_vals = [p["in_bps"] for p in lp_pts if p["in_bps"] > 0]
                logica_principal["hist_bps_max"] = max(lp_vals) if lp_vals else 0
                # Agregar out_bps_now y cap_gbps
                pts_v = [p for p in lp_pts if p.get("out_bps",0) > 0]
                logica_principal["out_bps_now"] = pts_v[-1]["out_bps"] if pts_v else 0
                # Calcular capacidad desde config.json (capacidad nominal configurada)
                config_data = load_json(CONFIG_FILE, {})
                cap_gbps_conf = 0
                devname_r = router.get("name", devname)
                for cr in config_data.get("routers_provider", []):
                    if cr.get("name","").upper() == devname_r.upper():
                        cap_gbps_conf = cr.get("capacidad_gbps", 0)
                        break
                if cap_gbps_conf > 0:
                    logica_principal["cap_gbps"] = float(cap_gbps_conf)
                else:
                    # Fallback: sumar interfaces fisicas up
                    speed_lp = 0
                    for iface in ifaces_actual:
                        if not es_logica_principal(iface["ifname"]) and iface.get("oper",0)==1:
                            speed_lp += iface.get("speed",0) or 0
                    logica_principal["cap_gbps"] = round(speed_lp/1000,1) if speed_lp>0 else 0

        router_ext = {
            **router,
            "nombre":           router.get("name", devname),
            "logica_principal": logica_principal,
        }
        routers_con_ifaces.append(router_ext)
        anom = analizar_router(router, ifaces_actual, historico)
        todas_anomalias.extend(anom)

    # Conmutaciones
    pares = generar_pares(routers_con_ifaces)
    todas_anomalias.extend(detectar_conmutaciones(pares, todas_anomalias))

    # Ordenar
    orden_sev  = {"critica":0,"importante":1,"advertencia":2,"info":3}
    orden_tipo = {"caida_bundle":0,"miembro_down":1,"saturacion":2,"cap_perdida":3,
                  "errores":4,"descartes":5,"conmutacion":6}
    todas_anomalias.sort(key=lambda a:(
        orden_sev.get(a["sev"],9),
        orden_tipo.get(a["tipo"],9),
        a.get("router","")
    ))

    # Filtrar ACKs
    acks    = load_ack()
    hoy     = date.today().strftime("%d/%m/%Y")
    ack_set = {(a["router"],a["tipo"],a.get("ifname",""))
               for a in acks if a.get("fecha")==hoy}
    sin_ack = [a for a in todas_anomalias
               if (a["router"],a["tipo"],a.get("ifname","")) not in ack_set]
    for a in sin_ack:
        a["fecha"] = hoy

    # Resumen
    criticas = len([a for a in sin_ack if a["sev"]=="critica"])
    resumen  = {
        "total":         len(routers),
        "con_ifaces":    len(routers_con_ifaces),
        "en_alerta":     criticas,
        "saturaciones":  len([a for a in sin_ack if a["tipo"]=="saturacion"]),
        "caidas":        len([a for a in sin_ack if a["tipo"]=="caida_bundle"]),
        "cap_perdidas":  len([a for a in sin_ack if a["tipo"]=="cap_perdida"]),
        "conmutaciones": len([a for a in sin_ack if a["tipo"]=="conmutacion"]),
        "errores":       len([a for a in sin_ack if a["tipo"]=="errores"]),
        "normales":      max(0, len(routers_con_ifaces)-criticas),
    }

    # Routers para mostrar en grupos
    routers_out = []
    for r in routers_con_ifaces:
        lp = r.get("logica_principal")
        in_gbps  = round(lp["in_bps_now"]/1e9,2)  if lp else 0
        out_gbps = round(lp.get("out_bps_now",0)/1e9,2) if lp else 0
        cap_gbps = lp.get("cap_gbps",0) if lp else 0
        pct_in   = round(in_gbps/cap_gbps*100,1) if cap_gbps>0 else 0
        pct_out  = round(out_gbps/cap_gbps*100,1) if cap_gbps>0 else 0
        routers_out.append({
            "devname": r.get("name", r.get("devname","")),
            "grupo":   r.get("rol","router-pe"),
            "ciudad":  r.get("ciudad",""),
            "in_gbps": in_gbps,
            "out_gbps":out_gbps,
            "cap_gbps":cap_gbps,
            "pct_in":  pct_in,
            "pct_out": pct_out,
            "alerta":  any(a["router"].startswith(r.get("name","---")) for a in sin_ack if a["sev"]=="critica"),
            "max_gbps":0,
        })

    # Detectar alarmas resueltas (estaban activas en poll anterior, ya no)
    ahora = ahora_str()
    prev = load_alertas_rt()
    prev_keys = {(a["router"],a["tipo"],a.get("ifname","")): a
                 for a in prev.get("alarmas",[]) if a.get("activa",True)}
    curr_keys = {(a["router"],a["tipo"],a.get("ifname",""))
                 for a in sin_ack if a.get("activa",True)}
    resueltas = []
    for key, a_prev in prev_keys.items():
        if key not in curr_keys:
            resueltas.append({
                **a_prev,
                "activa":    False,
                "detectado": ahora,
                "valor":     "Recuperado",
                "desc":      a_prev["desc"].replace("CAIDO","RECUPERADO").replace("paso a Down","recuperada") + f" — Resuelta a las {ahora}",
            })

    # Combinar actuales + resueltas para mostrar en la web
    todas_display = sin_ack + resueltas

    # Agregar alertas de Grafana Alertmanager ANTES de guardar
    try:
        alertas_grafana = grafana_get_alertas()
        if alertas_grafana:
            print(f"[Grafana Alertas] {len(alertas_grafana)} alertas activas")
            alertas_no_silenciadas = [a for a in alertas_grafana if not alerta_silenciada(a.get("alert_uid",""), a.get("alertname",""))]
            todas_display.extend(alertas_no_silenciadas)
    except Exception as e:
        print(f"[Grafana Alertas] Error integrando: {e}")

    # Recalcular resumen incluyendo alertas Grafana
    activas_total = [a for a in todas_display if a.get("activa", True)]
    criticas_total = len([a for a in activas_total if a.get("sev") == "critica"])
    resumen["en_alerta"]     = criticas_total
    resumen["saturaciones"]  = len([a for a in activas_total if a.get("tipo") == "saturacion"])
    resumen["caidas"]        = len([a for a in activas_total if a.get("tipo") in ("caida_bundle","miembro_down","equipos_down")])
    resumen["cap_perdidas"]  = len([a for a in activas_total if a.get("tipo") == "cap_perdida"])
    resumen["conmutaciones"] = len([a for a in activas_total if a.get("tipo") == "conmutacion"])
    resumen["errores"]       = len([a for a in activas_total if a.get("tipo") in ("errores","descartes","recurso")])
    resumen["normales"]      = max(0, resumen["total"] - len(activas_total))
    # Guardar en disco
    save_json(ALERTAS_RT, {
        "ts":      ahora,
        "alarmas": todas_display,
        "routers": routers_out,
        "resumen": resumen,
    })

    # Actualizar historial del dia (InfluxDB + Grafana)
    sat_display=[a for a in todas_display if a.get("tipo")=="saturacion"]
    print("[POLL] Saturacion en todas_display:", len(sat_display), flush=True)
    actualizar_hist(todas_display)
    mover_a_archivo()

    with _lock:
        _ultimo_poll = datetime.now()

    print(f"[GOC Poll] FIN {ahora_str()} — "
          f"routers:{consultados} alarmas:{len(sin_ack)} criticas:{criticas}")

# ---------------------------------------------------------------------------
# GRAFANA ALERTMANAGER — alertas activas en tiempo real
# ---------------------------------------------------------------------------
GRAFANA_ALERT_FOLDERS = [
    "CLLANOS", "MPLS/ISP",
    "MPLS/ISP/01", "MPLS/ISP/02", "MPLS/ISP/07"
]

# Silencios por alert rule UID de Grafana (granular)
# Se cargan dinamicamente desde las alertas activas


SILENCIOS_FILE = os.path.join(DATA_DIR, "silencios_grafana.json")

def load_silencios():
    return load_json(SILENCIOS_FILE, {})

def save_silencios(silencios):
    save_json(SILENCIOS_FILE, silencios)

def alerta_silenciada(alert_rule_uid, alertname):
    """Verifica si una alerta especifica esta silenciada por UID o nombre."""
    silencios = load_silencios()
    key = alert_rule_uid or alertname
    if not key or key not in silencios:
        return False
    s = silencios[key]
    if s.get("indefinido"):
        return True
    hasta = s.get("hasta")
    if hasta:
        try:
            dt_hasta = datetime.strptime(hasta, "%d/%m/%Y %H:%M")
            if datetime.now() < dt_hasta:
                return True
            else:
                del silencios[key]
                save_silencios(silencios)
                return False
        except Exception:
            return False
    return False

def limpiar_router(nombre):
    """Elimina sufijos de dominio y modelo de los nombres de routers."""
    import re as _re
    sufijos = [
        r'\.vtr\.cl', r'\.clarochile\.cl', r'\.telmex\.cl',
        r'\.claro\.cl', r'_ASR9010', r'_ASR9006', r'_ASR9922',
        r'_C7609S', r'_MX960', r'_MX480-re0', r'_MX480',
        r'_QFX', r'_re0', r'-re0',
    ]
    for s in sufijos:
        nombre = _re.sub(s, '', nombre, flags=_re.IGNORECASE)
    return nombre.strip()

UMBRALES_FILE = os.path.join(DATA_DIR, "umbrales_grafana.json")

def get_umbral_grafana(alert_uid):
    """Obtiene el umbral configurado en Grafana para una alerta. Cachea resultado."""
    if not alert_uid:
        return None
    cache = load_json(UMBRALES_FILE, {})
    if alert_uid in cache:
        return cache[alert_uid]
    try:
        url = f"{GRAFANA_URL}/api/v1/provisioning/alert-rules/{alert_uid}"
        headers = {"Authorization": f"Bearer {GRAFANA_TOKEN}"}
        r = req.get(url, headers=headers, timeout=10, verify=False)
        if r.status_code != 200:
            return None
        data = r.json()
        umbral = None
        for bloque in data.get("data", []):
            modelo = bloque.get("model", {})
            for cond in modelo.get("conditions", []):
                ev = cond.get("evaluator", {})
                params = ev.get("params", [])
                if params:
                    umbral = params[0]
                    break
            if umbral is not None:
                break
        cache[alert_uid] = umbral
        save_json(UMBRALES_FILE, cache)
        return umbral
    except Exception as e:
        print(f"[Grafana Umbral] Error {alert_uid}: {e}")
        return None

def construir_desc_grafana(nombre, tipo, router, ifname, serie, alert_uid):
    """Construye descripcion estructurada segun tipo de alarma."""
    router_clean = limpiar_router(router)
    if tipo == "recurso":
        umbral = get_umbral_grafana(alert_uid)
        modulo = ifname or "modulo desconocido"
        desc = nombre
        if umbral is not None:
            desc = f"{nombre} (umbral: {umbral}%)"
        return f"{router_clean} | Modulo: {modulo} | {desc}"
    elif tipo == "equipos_down":
        desc = nombre.replace("[ALERTA] ", "").replace("[alerta] ", "")
        return f"[NE DOWN] {router_clean} | {desc}"
    elif tipo in ("caida_bundle", "miembro_down"):
        if ifname:
            return f"{router_clean} | Interfaz: {ifname} | {nombre}"
        return f"{router_clean} | {nombre}"
    elif tipo in ("errores", "descartes"):
        if ifname:
            return f"{router_clean} | Interfaz: {ifname} | {nombre}"
        return f"{router_clean} | {nombre}"
    else:
        if serie:
            return f"{nombre}. Serie: {serie[:60]}"
        return nombre

def categoria_silenciada(categoria):
    """Compatibilidad - siempre False ahora."""
    return False
GRAFANA_ALERT_EXCLUDE = ["DatasourceNoData"]

def grafana_get_alertas_raw():
    """Retorna alertas Grafana sin aplicar silencios, para el panel admin."""
    url = f"{GRAFANA_URL}/api/alertmanager/grafana/api/v2/alerts"
    params = {"active": "true", "silenced": "false"}
    headers = {"Authorization": f"Bearer {GRAFANA_TOKEN}"}
    r = req.get(url, params=params, headers=headers, timeout=30, verify=False)
    alertas = r.json()
    result = []
    for a in alertas:
        labels  = a.get("labels", {})
        nombre  = labels.get("alertname", "")
        folder  = labels.get("grafana_folder", "")
        serie   = labels.get("Serie", "")
        state   = a.get("status", {}).get("state", "")
        if nombre in GRAFANA_ALERT_EXCLUDE:
            continue
        folder_ok = any(f in folder for f in GRAFANA_ALERT_FOLDERS)
        if not folder_ok:
            continue
        tipo, sev, categoria = clasificar_alerta_grafana(nombre, folder)
        if categoria is None:
            continue
        router, ifname = parsear_serie_grafana(serie, labels)
        result.append({
            "alertname": nombre,
            "alert_uid": labels.get("__alert_rule_uid__",""),
            "router":    router or nombre[:50],
            "ifname":    ifname,
            "categoria": categoria,
            "activa":    state == "active",
        })
    return result

def grafana_get_alertas():
    """
    Consulta la API de Alertmanager de Grafana y retorna alertas activas
    relevantes para el GOC Core MPLS/ISP.
    """
    url = f"{GRAFANA_URL}/api/alertmanager/grafana/api/v2/alerts"
    params = {"active": "true", "silenced": "false"}
    headers = {"Authorization": f"Bearer {GRAFANA_TOKEN}"}
    try:
        r = req.get(url, params=params, headers=headers, timeout=30, verify=False)
        alertas = r.json()
    except Exception as e:
        print(f"[Grafana Alertas] Error: {e}")
        return []

    relevantes = []
    for a in alertas:
        labels   = a.get("labels", {})
        nombre   = labels.get("alertname", "")
        folder   = labels.get("grafana_folder", "")
        serie    = labels.get("Serie", "")
        state    = a.get("status", {}).get("state", "")
        starts   = a.get("startsAt", "")
        ends     = a.get("endsAt", "")
        url_alerta = a.get("generatorURL", "")

        # Excluir ruido
        if nombre in GRAFANA_ALERT_EXCLUDE:
            continue

        # Incluir todas las alertas relevantes
        folder_ok = (
            any(f in folder for f in GRAFANA_ALERT_FOLDERS) or
            "CALIDAD FIJA" in folder or
            "calidad fija" in folder.lower()
        )
        if not folder_ok:
            continue

        # Determinar tipo, severidad y categoria
        tipo, sev, categoria = clasificar_alerta_grafana(nombre, folder)

        # Saltar alertas sin categoria (calidad fija, etc.)
        if categoria is None:
            continue
        # Verificar si la alerta especifica esta silenciada
        alert_uid = labels.get("__alert_rule_uid__", "")
        if alerta_silenciada(alert_uid, nombre):
            continue

        # Parsear router e interfaz desde Serie o labels directamente
        router, ifname = parsear_serie_grafana(serie, labels)

        # Parsear timestamp inicio
        ts_inicio = ""
        try:
            from datetime import timezone
            dt = datetime.strptime(starts[:19], "%Y-%m-%dT%H:%M:%S")
            dt = dt.replace(tzinfo=timezone.utc).astimezone()
            ts_inicio = dt.strftime("%d/%m/%Y %H:%M")
        except Exception:
            ts_inicio = starts[:16]

        router_limpio = limpiar_router(router or nombre[:50])
        desc_struct   = construir_desc_grafana(nombre, tipo, router or nombre[:50], ifname, serie, alert_uid)
        descriptor_rel = extraer_descriptor_relevante(serie)
        grafana_url_panel = construir_grafana_url(descriptor_rel)
        relevantes.append({
            "tipo":       tipo,
            "sev":        sev,
            "router":     router_limpio,
            "ifname":     ifname,
            "devif":      "",
            "alertname":  nombre,
            "alert_uid":  alert_uid,
            "desc":       desc_struct,
            "valor":      state.upper(),
            "detectado":  ts_inicio,
            "activa":     state == "active",
            "fecha":      date.today().strftime("%d/%m/%Y"),
            "fuente":     "grafana",
            "categoria":  categoria,
            "url":        url_alerta,
            "fingerprint": a.get("fingerprint", ""),
            "descriptor":    descriptor_rel,
            "grafana_panel": load_grafana_links().get(a.get("fingerprint",""), grafana_url_panel),
        })

    return relevantes



# === TABLA OFICIAL DE LABELS GOC ===
GOC_CATEGORIA_MAP = {
    "equipos_core":     "equipos_core",
    "equipos":          "equipos_core",
    "enlaces_core":     "enlaces_core",
    "enlaces":          "enlaces_core",
    "utilizacion_core": "utilizacion_core",
    "utilizacion":      "utilizacion_core",
    "errores_core":     "errores_core",
    "errores":          "errores_core",
    "cpu_memoria":      "cpu_memoria",
    "cpu":              "cpu_memoria",
    "drp_core":         "drp_core",
    "drp":              "drp_core",
}

GOC_TIPO_MAP = {
    "equipos_down":  "equipos_down",
    "caida_bundle":  "caida_bundle",
    "caida":         "caida_bundle",
    "miembro_down":  "miembro_down",
    "saturacion":    "saturacion",
    "alerta":        "alerta",
    "errores":       "errores",
    "descartes":     "descartes",
    "recurso":       "recurso",
    "drp_down":      "drp_down",
    "drp_cap":       "drp_cap",
    "drp_activo":    "drp_activo",
    "drp":           "drp_down",  # backward compat
}

def clasificar_alerta_grafana(nombre, folder):
    """Clasifica tipo, severidad y categoria de la alerta Grafana."""
    nombre_l = nombre.lower()
    folder_l  = folder.lower()

    # Excluir calidad fija
    if "calidad fija" in folder_l:
        return None, None, None

    # Categoria
    if "drp" in folder_l or "drp" in nombre_l:
        categoria = "drp_core"
        # Subtipo DRP segun alertname
        if "trafico out" in nombre_l or "trafico in" in nombre_l:
            return "drp_activo", "importante", "drp_core"
        elif "capacidad" in nombre_l:
            return "drp_cap", "importante", "drp_core"
    elif any(x in nombre_l for x in ["cpu","memoria","memory","temperatura"]):
        categoria = "cpu_memoria"
    elif any(x in nombre_l for x in ["error","discard"]):
        categoria = "errores_core"
    elif any(x in nombre_l for x in ["no operativo","equipo core","equipo isp","caida de equipo","caída de equipo"]):
        categoria = "equipos_core"
    elif any(x in nombre_l for x in ["95%","0% utilizacion","utilizaci"]):
        categoria = "utilizacion_core"
    else:
        categoria = "enlaces_core"

    # Tipo y severidad
    if "drp" in folder_l or "drp" in nombre_l:
        if "trafico out" in nombre_l or "trafico in" in nombre_l or "trafico activo" in nombre_l or "activo" in nombre_l:
            tipo, sev = "drp_activo", "importante"
        elif "capacidad" in nombre_l:
            tipo, sev = "drp_cap", "importante"
        elif "down" in nombre_l or "caido" in nombre_l or "caído" in nombre_l:
            tipo, sev = "drp_down", "importante"
        else:
            tipo, sev = "drp_down", "importante"
    elif any(x in nombre_l for x in ["cpu","memoria","memory"]):
        tipo, sev = "recurso", "advertencia"
    elif any(x in nombre_l for x in ["error","discard"]):
        tipo, sev = "errores", "importante"
    elif any(x in nombre_l for x in ["no operativo","equipo core","equipo isp","caida de equipo","caída de equipo"]):
        tipo, sev = "equipos_down", "critica"
    elif "95%" in nombre_l:
        tipo, sev = "saturacion", "critica"
    elif "0% utilizacion" in nombre_l or "utilizaci" in nombre_l:
        tipo, sev = "alerta", "advertencia"
    elif any(x in nombre_l for x in ["caida","caída","down","enlaces","fisico","logico"]):
        tipo, sev = "caida_bundle", "critica"
    else:
        tipo, sev = "alerta", "advertencia"

    return tipo, sev, categoria




# URL base dashboard ISP/Internacional
GRAFANA_ISP_URL = "https://clarochile.grafana.net/d/clhv9r6/03-1-trafico-internacional-nacional-contenido?orgId=1&from=now-24h&to=now&timezone=browser&refresh=5m"

# Mapeo descriptor -> var-isp (nombre proveedor en Grafana)
DESCRIPTOR_ISP_MAP = {
    "PITINTERNACIONAL LEVEL3":   "PITINTERNACIONAL_LEVEL3",
    "PITINTERNACIONAL COGENT":   "PITINTERNACIONAL_COGENT",
    "PITINTERNACIONAL":          "PITINTERNACIONAL_LEVEL3",
    "TATA":                      "tata",
    "PIT GCORE":                 "GCORE",
    "PIT GOOGLE":                "GOOGLE",
    "PIT FACEBOOK":              "FACEBOOK",
    "PIT AMAZON":                "AMAZON",
    "PIT AKAMAI":                "AKAMAI",
    "PIT MICROSOFT":             "MICROSOFT",
    "PIT RIOTGAME":              "RIOTGAME",
    "PIT CLOUDFLARE":            "CLOUDFLARE",
    "PIT VALVE":                 "VALVE",
    "PIT EDGEUNO":               "EDGEUNO",
    "PIT CHILE":                 "PITCHILE",
    "PIT ENTEL":                 "ENTEL",
    "PIT MOVISTAR":              "MOVISTAR",
    "PIT NAP":                   "NAP",
    "PIT CLARO":                 "CLARO",
    "PIT GTD":                   "GTD",
    "PIT CENTURY":               "CENTURY",
    "PIT IFX":                   "IFX",
    "PIT DISNEY":                "DISNEY",
    "PIT FASTLY":                "FASTLY",
}

# Mapeo inverso proveedor -> descriptor (para busquedas en chatbot)
PROVEEDOR_DESCRIPTOR_MAP = {
    "cirion":       "PITINTERNACIONAL_LEVEL3",
    "level3":       "PITINTERNACIONAL_LEVEL3",
    "cogent":       "PITINTERNACIONAL_COGENT",
    "cogen":        "PITINTERNACIONAL_COGENT",
    "tata":         "TATA",
    "gcore":        "PIT_GCORE",
    "google":       "PIT_GOOGLE",
    "facebook":     "PIT_FACEBOOK",
    "amazon":       "PIT_AMAZON",
    "akamai":       "PIT_AKAMAI",
    "microsoft":    "PIT_MICROSOFT",
    "riotgame":     "PIT_RIOTGAME",
    "riot":         "PIT_RIOTGAME",
    "cloudflare":   "PIT_CLOUDFLARE",
    "valve":        "PIT_VALVE",
    "edgeuno":      "PIT_EDGEUNO",
    "chile":        "PIT_CHILE",
    "entel":        "PIT_ENTEL",
    "movistar":     "PIT_MOVISTAR",
    "nap":          "PIT_NAP",
    "gtd":          "PIT_GTD",
    "century":      "PIT_CENTURY",
    "centurylink":  "PIT_CENTURY",
    "ifx":          "PIT_IFX",
    "disney":       "PIT_DISNEY",
    "fastly":       "PIT_FASTLY",
}


PROVEEDOR_NOMBRE_HUMANO = {
    "PITINTERNACIONAL_LEVEL3":  "Level3 (Cirion)",
    "PITINTERNACIONAL_COGENT":  "Cogent",
    "PITINTERNACIONAL":         "Internacional",
    "TATA":                     "TATA",
    "PIT_GCORE":                "GCore",
    "PIT_GOOGLE":               "Google",
    "PIT_FACEBOOK":             "Facebook/Meta",
    "PIT_AMAZON":               "Amazon (AWS)",
    "PIT_AKAMAI":               "Akamai",
    "PIT_MICROSOFT":            "Microsoft",
    "PIT_RIOTGAME":             "Riot Games",
    "PIT_CLOUDFLARE":           "Cloudflare",
    "PIT_VALVE":                "Valve/Steam",
    "PIT_EDGEUNO":              "Edgeuno",
    "PIT_CHILE":                "PIT Chile",
    "PIT_ENTEL":                "Entel",
    "PIT_MOVISTAR":             "Movistar",
    "PIT_NAP":                  "NAP Chile",
    "PIT_CLARO":                "Claro",
    "PIT_GTD":                  "GTD",
    "PIT_CENTURY":              "CenturyLink",
    "PIT_IFX":                  "IFX",
    "PIT_DISNEY":               "Disney",
    "PIT_FASTLY":               "Fastly",
}

def humanizar_router(devname):
    import re as _re
    name = devname
    name = _re.sub(r"\.telmex\.cl$|\.vtr\.cl$|\.clarochile\.cl$", "", name)
    name = name.replace("_", " ").replace("-", " ")
    name = _re.sub(r"\s*(ASR9010|ASR9006|ASR9922|MX480|MX960|C7609S|re0)\b", "", name, flags=_re.IGNORECASE)
    return name.strip()

def humanizar_gbps(gbps):
    if gbps >= 1000:
        return str(round(gbps/1000, 2)) + " Tbps"
    elif gbps >= 1:
        return str(round(gbps, 1)) + " Gbps"
    elif gbps >= 0.001:
        return str(round(gbps*1000, 0)) + " Mbps"
    else:
        return "0 Mbps"

def formatear_respuesta_isp(proveedor_isp, res_t=None, total_t=0, res_c=None, total_c=0, grafana_url=""):
    nombre = PROVEEDOR_NOMBRE_HUMANO.get(proveedor_isp, proveedor_isp.replace("_"," ").title())
    lineas = []
    if res_t is not None and res_c is not None:
        lineas.append("Trafico y capacidad del enlace con " + nombre + ":")
        lineas.append("")
        lineas.append("El trafico total de entrada es de " + humanizar_gbps(total_t) + ", distribuido en " + str(len(res_t)) + " nodo(s):")
        for r in res_t:
            lineas.append("  * " + humanizar_router(r["devname"]) + ": " + humanizar_gbps(r["in_gbps"]) + " de entrada y " + humanizar_gbps(r["out_gbps"]) + " de salida")
        lineas.append("")
        lineas.append("La capacidad contratada total es de " + humanizar_gbps(total_c) + ":")
        for r in res_c:
            lineas.append("  * " + humanizar_router(r["devname"]) + ": " + humanizar_gbps(r["cap_gbps"]) + " de capacidad")
    elif res_t is not None:
        lineas.append("Trafico del enlace con " + nombre + ":")
        lineas.append("")
        lineas.append("El trafico total de entrada es de " + humanizar_gbps(total_t) + ", distribuido asi:")
        for r in res_t:
            lineas.append("  * " + humanizar_router(r["devname"]) + ": " + humanizar_gbps(r["in_gbps"]) + " de entrada y " + humanizar_gbps(r["out_gbps"]) + " de salida")
    elif res_c is not None:
        lineas.append("Capacidad del enlace con " + nombre + ":")
        lineas.append("")
        lineas.append("La capacidad total contratada es de " + humanizar_gbps(total_c) + ":")
        for r in res_c:
            lineas.append("  * " + humanizar_router(r["devname"]) + ": " + humanizar_gbps(r["cap_gbps"]) + " de capacidad")
    if grafana_url:
        lineas.append("")
        lineas.append("Ver grafico en Grafana: " + grafana_url)
    return chr(10).join(lineas)
def formatear_respuesta_ciudades(datos_ciudades, metrica="trafico"):
    lineas = []
    for ciudad, data in datos_ciudades.items():
        total_in = data.get("total_in_gbps", 0)
        total_out = data.get("total_out_gbps", 0)
        interfaces = data.get("interfaces", [])
        if metrica == "capacidad":
            lineas.append(ciudad + " - Capacidad total: " + humanizar_gbps(total_in))
        else:
            lineas.append(ciudad + " - Trafico: " + humanizar_gbps(total_in) + " entrada / " + humanizar_gbps(total_out) + " salida")
        for ifc in interfaces:
            router = humanizar_router(ifc.get("devname",""))
            ifname = ifc.get("ifname","")
            if metrica == "capacidad":
                cap = ifc.get("in_gbps", 0)
                lineas.append("  - " + router + " (" + ifname + "): " + humanizar_gbps(cap) + " capacidad")
            else:
                in_g = ifc.get("in_gbps", 0)
                pct = ifc.get("pct", 0)
                lineas.append("  - " + router + " (" + ifname + "): " + humanizar_gbps(in_g) + " entrada (" + str(pct) + "% uso)")
    return chr(10).join(lineas)

def construir_grafana_url(descriptor):
    """Construye URL de Grafana segun el descriptor de la alarma."""
    if not descriptor:
        return ""
    # ISP/Peering/Contenido
    var_isp = DESCRIPTOR_ISP_MAP.get(descriptor, "")
    if var_isp:
        return GRAFANA_ISP_URL + "&var-isp=" + var_isp
    return ""

def extraer_descriptor_relevante(serie):
    """Busca keyword GOC en cualquier parte del descriptor y retorna solo la keyword."""
    if not serie:
        return ""
    import re as _re
    # Usar toda la serie para buscar
    serie_upper = serie.upper()
    # Lista oficial de keywords - ordenadas de mas especifica a menos
    KEYWORDS = [
        "PITINTERNACIONAL_LEVEL3","PITINTERNACIONAL_COGENT","PITINTERNACIONAL",
        "PIT_GCORE","PIT_GOOGLE","PIT_FACEBOOK","PIT_AMAZON","PIT_AKAMAI",
        "PIT_MICROSOFT","PIT_RIOTGAME","PIT_CLOUDFLARE","PIT_VALVE","PIT_EDGEUNO",
        "PIT_CHILE","PIT_ENTEL","PIT_MOVISTAR","PIT_NAP","PIT_CLARO","PIT_GTD",
        "PIT_CENTURY","PIT_IFX","PIT_DISNEY","PIT_FASTLY","TATA",
        "IGWBBIPITDOWNLINK","IGWBBHPEIDOWNLINK","IGWPITHPEDOWNLINK",
        "IGWAGGBBIDOWNLINK","IGWAGGQFXUPNLINK","IGWBBIBORDE","IGWINTERLINK","IGWBBP",
        "IPTV_CACHE_CDN","BBPINTERLINK","BBPUPLINKS","BBPUPLINKR","BBPUPLINK",
        "BBPIGW","BBINTERLINK","BBDRPUP","BBPREG","BBUPLINK","BBMOVIL","BBTVD",
        "BBCDN","BBIPTV","BPREGP","BPBBI","HRAN",
    ]
    for kw in KEYWORDS:
        if kw in serie_upper:
            # Retornar solo la keyword limpia
            return kw.replace("_", " ")
    return ""

def parsear_serie_grafana(serie, labels=None):
    """
    Extrae router e interfaz desde el campo Serie o directamente desde labels.
    Prioridad: Serie -> labels.devname + labels.ifName
    """
    if labels is None:
        labels = {}

    router, ifname = "", ""

    if serie and serie.strip():
        # Parsear desde Serie: DEVNAME_|_IFNAME_|_descriptor
        partes = [p.strip().strip("_") for p in serie.split("|")]
        router = partes[0] if partes else ""
        ifname = partes[1] if len(partes) > 1 else ""
    else:
        # Leer directamente desde labels de Grafana
        router = labels.get("devname", "") or labels.get("name", "")
        ifname = labels.get("ifName", "") or labels.get("tarjeta", "")

    # Limpiar guiones bajos del router name
    router = router.replace("_", " ").strip()
    return router, ifname


def polling_loop():
    time.sleep(10)
    if not get_cache():
        try:
            actualizar_cache()
        except Exception as e:
            print(f"[GOC] Error cache: {e}")
    try:
        ejecutar_polling()
    except Exception as e:
        print(f"[GOC] Error primer poll: {e}")
    while True:
        time.sleep(POLL_SECS)
        try:
            ejecutar_polling()
        except Exception as e:
            print(f"[GOC] Error poll: {e}")

def iniciar_polling():
    global _polling_iniciado
    with _lock:
        if _polling_iniciado:
            return
        _polling_iniciado = True
    threading.Thread(target=polling_loop, daemon=True).start()
    print("[GOC] Polling iniciado")

def _delayed_init():
    time.sleep(5)
    iniciar_polling()
threading.Thread(target=_delayed_init, daemon=True).start()

# ---------------------------------------------------------------------------
# CORREO HTML via MAT
# ---------------------------------------------------------------------------
def badge_sev(sev):
    c = {"critica":"#991b1b","importante":"#b45309","advertencia":"#92400e","info":"#1e40af"}
    b = {"critica":"#fee2e2","importante":"#fef3c7","advertencia":"#fffbeb","info":"#eff6ff"}
    return (f"<span style='background:{b.get(sev,'#f3f4f6')};color:{c.get(sev,'#374151')};"
            f"padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;"
            f"border:1px solid {c.get(sev,'#d1d5db')}'>{sev.upper()}</span>")

def html_tabla(alarmas, titulo, color, bg):
    if not alarmas:
        return ""
    rows = "".join(
        f"<tr style='border-bottom:1px solid #e5e7eb'>"
        f"<td style='padding:8px 10px;font-weight:700'>{a.get('router','')}</td>"
        f"<td style='padding:8px 10px'>{badge_sev(a.get('sev','info'))}</td>"
        f"<td style='padding:8px 10px;font-size:11px;color:#6b7280'>{a.get('tipo','').upper()}</td>"
        f"<td style='padding:8px 10px;font-size:12px'>{a.get('ifname','')}</td>"
        f"<td style='padding:8px 10px'>{a.get('desc','')}</td>"
        f"<td style='padding:8px 10px;font-size:11px;color:#6b7280'>{a.get('detectado','')}</td>"
        f"</tr>"
        for a in alarmas
    )
    return (f"<h3 style='margin:24px 0 8px;color:{color}'>{titulo} ({len(alarmas)})</h3>"
            f"<table border='0' style='border-collapse:collapse;width:100%;font-size:13px'>"
            f"<thead><tr style='background:{bg}'>"
            f"<th style='text-align:left;padding:8px 10px;color:#fff'>Router</th>"
            f"<th style='text-align:left;padding:8px 10px;color:#fff'>Severidad</th>"
            f"<th style='text-align:left;padding:8px 10px;color:#fff'>Tipo</th>"
            f"<th style='text-align:left;padding:8px 10px;color:#fff'>Interfaz</th>"
            f"<th style='text-align:left;padding:8px 10px;color:#fff'>Descripcion</th>"
            f"<th style='text-align:left;padding:8px 10px;color:#fff'>Detectado</th>"
            f"</tr></thead><tbody>{rows}</tbody></table>")

def enviar_correo_mat(todas, turno="", ingeniero="GOC", fecha="", secciones=None, html_reporte=None):
    import re as _re
    activas   = [a for a in todas if a.get("activa", True)]
    resueltas = [a for a in todas if not a.get("activa", True)]
    ncrit     = len([a for a in activas if a.get("sev") == "critica"])
    subject   = f"GOC - Revision Diaria Core MPLS/ISP - Turno {turno} - {fecha or ahora_str()}"
    if ncrit > 0:
        subject = "[ALERTA] " + subject
    elif not activas:
        subject = "[OK] " + subject

    cats = [
        {"id":"rev_enlaces","label":"Enlaces Core — Interfaces Down/Up",
         "fn": lambda e: (e.get("tipo") in ("caida_bundle","miembro_down")) and e.get("categoria") not in ("equipos_core","utilizacion_core","drp_core")},
        {"id":"rev_equipos","label":"Equipos Core — NE Down",
         "fn": lambda e: e.get("tipo") == "equipos_down" or e.get("categoria") == "equipos_core"},
        {"id":"rev_util","label":"Utilizacion — Interfaces Core",
         "fn": lambda e: e.get("tipo") == "saturacion" or (e.get("tipo") == "caida_bundle" and e.get("categoria") == "utilizacion_core") or e.get("categoria") == "utilizacion_core"},
        {"id":"rev_errores","label":"Errores/Discard — Interfaces Core",
         "fn": lambda e: e.get("tipo") in ("errores","descartes") or e.get("categoria") == "errores_core"},
        {"id":"rev_cpu","label":"CPU/Memoria — Equipos Core",
         "fn": lambda e: e.get("tipo") == "recurso" or e.get("categoria") == "cpu_memoria"},
        {"id":"rev_drp","label":"DRP Core",
         "fn": lambda e: e.get("tipo") == "drp" or e.get("categoria") == "drp_core"},
    ]

    def item_html(e):
        color  = "#dc2626" if e.get("activa") else "#059669"
        estado = "ACTIVA" if e.get("activa") else ("RESUELTA (" + e["duracion"] + ")" if e.get("duracion") else "RESUELTA")
        router = e.get("router","")
        ifname = " [" + e["ifname"] + "]" if e.get("ifname") else ""
        desc   = e.get("desc","")[:100]
        return ("<div style='padding:5px 12px;font-size:12px;border-bottom:1px solid #f3f4f6'>"
                "<strong>" + router + ifname + "</strong> — " + desc +
                " <span style='color:" + color + ";font-weight:600'>" + estado + "</span></div>")

    def cat_html(cat):
        evs_cat = [e for e in todas if cat["fn"](e)]
        evs_act = [e for e in evs_cat if e.get("activa")]
        evs_res = [e for e in evs_cat if not e.get("activa")]
        coment  = ""
        if secciones:
            sec = next((s for s in secciones if s.get("id") == cat["id"]), None)
            if sec and sec.get("comentario"):
                coment = "<div style='background:#fffbeb;border:1px solid #fde68a;padding:6px 12px;margin:4px 0;font-size:12px'><b>Comentario:</b> " + sec["comentario"] + "</div>"
        bg     = "#fef2f2" if evs_act else "#f9fafb"
        border = "#da291c" if evs_act else "#d1d5db"
        cntlbl = str(len(evs_act)) + " activas" if evs_act else "Sin activas"
        cntclr = "#dc2626" if evs_act else "#059669"
        html   = ("<div style='margin-bottom:10px;border:1px solid " + border + ";border-radius:4px;overflow:hidden'>"
                  "<div style='background:" + bg + ";padding:6px 12px;display:flex;justify-content:space-between;align-items:center'>"
                  "<span style='font-size:12px;font-weight:700;color:#1f2937'>" + cat["label"] + "</span>"
                  "<span style='color:" + cntclr + ";font-weight:600'>" + cntlbl + "</span></div>"
                  + coment)
        if evs_act:
            html += "".join([item_html(e) for e in evs_act])
        if evs_res:
            html += "<div style='font-size:11px;font-weight:600;padding:3px 12px;background:#f0fdf4;color:#059669'>Resueltas (" + str(len(evs_res)) + ")</div>"
            html += "".join([item_html(e) for e in evs_res])
        if not evs_act and not evs_res:
            html += "<div style='padding:4px 12px;font-size:11px;color:#9ca3af'>Sin eventos</div>"
        html += "</div>"
        return html

    fecha_str = fecha or ahora_str()
    if html_reporte:
        html = html_reporte
    else:
        bloques = "".join([cat_html(c) for c in cats])
        fecha_str = fecha or ahora_str()
        html = ("<div style='font-family:Arial,sans-serif;max-width:960px;margin:0 auto'>"
                "<div style='background:#DA291C;padding:16px 24px;border-radius:6px 6px 0 0'>"
                "<h2 style='color:#fff;margin:0'>GOC - Revision Diaria Core MPLS/ISP</h2></div>"
                "<div style='background:#f9fafb;padding:12px 24px;border:1px solid #e5e7eb;border-top:none'>"
                "<table style='width:100%;font-size:13px'><tr>"
                "<td><b>Fecha:</b> " + fecha_str + "</td>"
                "<td><b>Turno:</b> " + turno + "</td>"
                "<td><b>Ingeniero:</b> " + ingeniero + "</td></tr><tr>"
                "<td><b>Total:</b> " + str(len(todas)) + "</td>"
                "<td><b>Activas:</b> <span style='color:#dc2626;font-weight:700'>" + str(len(activas)) + "</span></td>"
                "<td><b>Resueltas:</b> <span style='color:#059669;font-weight:700'>" + str(len(resueltas)) + "</span></td>"
                "</tr></table></div>"
                "<div style='padding:16px 24px;border:1px solid #e5e7eb;border-top:none;background:#fff'>"
                + bloques +
                "</div>"
                "<div style='background:#f3f4f6;padding:8px 24px;font-size:11px;color:#6b7280;"
                "border:1px solid #e5e7eb;border-top:none;border-radius:0 0 6px 6px'>Reporte GOC App - Claro VTR</div></div>")
    plain = ("GOC - Revision Diaria Core MPLS/ISP\n"
             "Turno: " + turno + " | Fecha: " + fecha_str + " | Ingeniero: " + ingeniero + "\n\n"
             "Se adjunta reporte de Revision Diaria Core MPLS/ISP.")

    payload = {"form_data": {
        "dest": load_correos(), "subject": subject,
        "plain_body": plain, "html_body": html,
    }}
    r = req.post(MAT_URL, json=payload, timeout=15,
                 headers={"Content-Type":"application/json","apikey":MAT_APIKEY},
                 verify=False)
    return r.status_code in [200,201,202], r.status_code, r.text[:300]

@app.route("/")
def index():
    return send_file("/app/index.html")

@app.route("/api/health")
def health():
    with _lock:
        ultimo = _ultimo_poll.strftime("%d/%m/%Y %H:%M") if _ultimo_poll else "nunca"
    cache = load_json(CACHE_FILE, {})
    return jsonify({
        "status": "ok", "ts": datetime.now().isoformat(),
        "ultimo_poll": ultimo,
        "routers_cache": len(cache.get("routers",[])),
        "cache_ts": cache.get("ts",""),
    })

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json or {}
    user = data.get("user","").strip()
    pwd  = data.get("password","").strip()
    users = load_users()
    if user in users and users[user]["password"] == pwd and users[user].get("activo", True):
        session.permanent = True
        session["user"] = user
        session["role"] = users[user]["role"]
        return jsonify({"ok":True,"role":users[user]["role"],"user":user})
    return jsonify({"ok":False,"error":"Usuario o contrasena incorrectos"}), 401

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"ok":True})

@app.route("/api/me")
def me():
    if "user" not in session:
        return jsonify({"logged":False})
    u    = session["user"]
    hora = datetime.now().hour
    turno_auto = "AM" if 6<=hora<14 else "PM" if 14<=hora<22 else "NOC"
    users = load_users()
    return jsonify({"logged":True,"user":u,"role":users.get(u,{}).get("role","viewer"),"turno_auto":turno_auto})


@app.route("/api/syslog/eventos")
@login_required
def syslog_eventos():
    horas = int(request.args.get("horas", 4))
    try:
        eventos = syslog_get_eventos(horas=horas)
        vmap = load_json(SYSLOG_VENDOR_MAP_FILE, {})
        totales = vmap.get("totales", {})
        activos_por_vendor = {}
        for ev in eventos:
            v = ev.get("vendor", "OTRO")
            activos_por_vendor.setdefault(v, set()).add(ev["equipo"])
        resumen_vendors = {}
        for v, total in totales.items():
            resumen_vendors[v] = {
                "activos": len(activos_por_vendor.get(v, set())),
                "total": total,
            }
        return jsonify({"ok": True, "eventos": eventos, "total": len(eventos), "resumen_vendors": resumen_vendors})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e), "eventos": []})

@app.route("/api/trafico")
@login_required
def trafico():
    """Lee desde alertas_rt.json — instantaneo, no hace queries."""
    rt = load_alertas_rt()
    r  = rt.get("resumen", {})
    return jsonify({
        "ok":       True,
        "ts":       rt.get("ts", ahora_str()),
        "anomalias":rt.get("alarmas", []),
        "routers":  rt.get("routers", []),
        "stats_24h":{},
        "resumen": {
            "total":         r.get("total",0),
            "en_alerta":     r.get("en_alerta",0),
            "saturaciones":  r.get("saturaciones",0),
            "caidas":        r.get("caidas",0),
            "cap_perdidas":  r.get("cap_perdidas",0),
            "conmutaciones": r.get("conmutaciones",0),
            "errores":       r.get("errores",0),
            "normales":      r.get("normales",0),
        }
    })


# === UTILIDADES DE NORMALIZACION ===
def normalizar_devname_regex(nombre):
    """Convierte nombre de router a regex flexible para InfluxDB.
    Ej: TEMU-PE1 -> TEMU[_-]PE1 (matchea TEMU_PE1_ASR9010.vtr.cl)
    """
    import re as _r
    # Limpiar y normalizar
    n = nombre.strip().upper()
    # Reemplazar separadores por regex flexible
    n = _r.sub(r'[-_]', '[_-]', n)
    # Reemplazar puntos
    n = n.replace('.', '[.]')
    return n

def buscar_devname_influx_real(nombre_usuario, timeout=10):
    """Busca el devname exacto en InfluxDB dado un nombre parcial."""
    regex = normalizar_devname_regex(nombre_usuario)
    q = 'SHOW TAG VALUES FROM "trafico" WITH KEY = "devname" WHERE "devname" =~ /' + regex + '/ AND time > now()-1h'
    try:
        data = influx_query(q, timeout=timeout)
        series = data.get("results",[{}])[0].get("series",[])
        devnames = []
        for s in series:
            for v in s.get("values",[]):
                devnames.append(v[1])
        return devnames
    except:
        return []

# === GRAFANA LINKS POR ALARMA ===
GRAFANA_LINKS_FILE = os.path.join(DATA_DIR, "grafana_links.json")
def load_grafana_links():
    return load_json(GRAFANA_LINKS_FILE, {})
def save_grafana_links(data):
    save_json(GRAFANA_LINKS_FILE, data)

@app.route("/api/alarma/grafana_link", methods=["POST"])
@login_required
def set_grafana_link():
    if session.get("role") != "admin":
        return jsonify({"ok":False,"error":"Sin permisos"}), 403
    data = request.json
    fp   = data.get("fingerprint","")
    url  = data.get("url","")
    if not fp:
        return jsonify({"ok":False,"error":"fingerprint requerido"}), 400
    links = load_grafana_links()
    if url:
        links[fp] = url
    else:
        links.pop(fp, None)
    save_grafana_links(links)
    return jsonify({"ok":True})

SILENCIOS_INST_FILE = os.path.join(DATA_DIR, "silencios_inst.json")

def load_silencios_inst():
    return load_json(SILENCIOS_INST_FILE, [])

def save_silencios_inst(data):
    save_json(SILENCIOS_INST_FILE, data)

@app.route("/api/silencios/inst", methods=["GET"])
@login_required
def get_silencios_inst():
    return jsonify({"ok": True, "silencios": load_silencios_inst()})

@app.route("/api/silencios/inst", methods=["POST"])
@admin_required
def add_silencio_inst():
    data = request.json
    silencios = load_silencios_inst()
    silencio = {
        "router":    data.get("router",""),
        "ifname":    data.get("ifname",""),
        "alertname": data.get("alertname",""),
        "usuario":   session.get("user",""),
        "ts":        datetime.now().strftime("%d/%m/%Y %H:%M")
    }
    # Evitar duplicados
    key = (silencio["router"], silencio["ifname"], silencio["alertname"])
    if not any((s["router"],s["ifname"],s["alertname"])==key for s in silencios):
        silencios.append(silencio)
        save_silencios_inst(silencios)
    return jsonify({"ok": True, "silencios": silencios})

@app.route("/api/silencios/inst/<int:idx>", methods=["DELETE"])
@admin_required
def del_silencio_inst(idx):
    silencios = load_silencios_inst()
    if 0 <= idx < len(silencios):
        silencios.pop(idx)
        save_silencios_inst(silencios)
    return jsonify({"ok": True, "silencios": silencios})


@app.route("/api/trafico/interfaz")
@login_required
def get_trafico_interfaz():
    """Retorna trafico y capacidad actual de una interfaz especifica."""
    devname = request.args.get("devname","").replace(" ","_")
    ifname  = request.args.get("ifname","")
    if not devname or not ifname:
        return jsonify({"ok":False,"error":"faltan parametros"})
    try:
        q_t = ("SELECT non_negative_derivative(mean(\"ifHCInOctets\"),1s)*8 AS in_bps,"
               " non_negative_derivative(mean(\"ifHCOutOctets\"),1s)*8 AS out_bps"
               " FROM \"trafico\""
               " WHERE \"devname\" =~ /"+devname+"/ AND \"ifName\" = '"+ifname+"'"
               " AND time > now()-10m"
               " GROUP BY time(100s),\"devname\",\"ifName\" fill(null)")
        q_c = ("SELECT last(\"ifSpeed\") AS speed"
               " FROM \"trafico\""
               " WHERE \"devname\" =~ /"+devname+"/ AND \"ifName\" = '"+ifname+"'"
               " AND time > now()-30m"
               " GROUP BY \"devname\",\"ifName\"")
        data_t = influx_query(q_t, timeout=15)
        data_c = influx_query(q_c, timeout=15)
        in_gbps, out_gbps, cap_gbps = 0, 0, 0
        series_t = data_t.get("results",[{}])[0].get("series",[])
        if series_t:
            vals = [v for v in series_t[0].get("values",[]) if v[1] is not None]
            if vals:
                v = vals[-1]
                in_gbps  = round((v[1] or 0)/1e9, 2)
                out_gbps = round((v[2] or 0)/1e9, 2) if len(v)>2 else 0
        series_c = data_c.get("results",[{}])[0].get("series",[])
        if series_c:
            vals_c = series_c[0].get("values",[])
            if vals_c and vals_c[0][1]:
                cap_gbps = round(vals_c[0][1]/1000, 1)
        return jsonify({"ok":True,"in_gbps":in_gbps,"out_gbps":out_gbps,"cap_gbps":cap_gbps})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e)})

@app.route("/api/trafico/historial/archivo")
@login_required
def trafico_historial_archivo():
    try:
        archivo = load_json(ARCHIVO_HIST, {"eventos": []})
        eventos = archivo.get("eventos", [])
        # Ordenar por ts_fin desc
        eventos_sorted = sorted(eventos, key=lambda x: x.get("ts_fin",""), reverse=True)
        return jsonify({"ok":True,"eventos":eventos_sorted,"total":len(eventos_sorted)})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e),"eventos":[]})

@app.route("/api/trafico/historial")
@login_required
def trafico_historial():
    import datetime as _dt
    h = load_hist()
    eventos = h.get("eventos", [])
    # Filtrar por fecha si viene parametro, sino ultimas 48h
    fecha_param = request.args.get("fecha","")
    ahora = _dt.datetime.now()
    if fecha_param:
        try:
            fecha_dt = _dt.datetime.strptime(fecha_param, "%Y-%m-%d")
            limite_ini = fecha_dt
            limite_fin = fecha_dt + _dt.timedelta(days=1)
        except:
            fecha_param = ""
    if not fecha_param:
        limite = ahora - _dt.timedelta(hours=48)
        limite_ini = limite
        limite_fin = ahora + _dt.timedelta(hours=1)
    # Si fecha anterior, incluir archivo historico
    if fecha_param:
        archivo = load_json(ARCHIVO_HIST, {"eventos": []})
        eventos = eventos + archivo.get("eventos", [])
    eventos_48h = []
    for ev in eventos:
        try:
            ts_str = ev.get("ts_inicio") or ev.get("ts") or ""
            if ts_str:
                ts = _dt.datetime.strptime(ts_str[:16], "%d/%m/%Y %H:%M")
                if limite_ini <= ts <= limite_fin:
                    eventos_48h.append(ev)
            else:
                if not fecha_param:
                    eventos_48h.append(ev)
        except:
            if not fecha_param:
                eventos_48h.append(ev)
    # Agrupar por router+interfaz
    grupos = {}
    for ev in eventos_48h:
        router = ev.get("router", "")
        ifname = ev.get("ifname", "")
        tipo   = ev.get("tipo", "")
        key    = router + "|" + ifname + "|" + tipo
        if key not in grupos:
            grupos[key] = {
                "router":      router,
                "ifname":      ifname,
                "tipo":        tipo,
                "sev":         ev.get("sev",""),
                "desc":        ev.get("desc",""),
                "categoria":   ev.get("categoria",""),
                "ocurrencias": [],
                "primera":     ev.get("ts_inicio",""),
                "ultima":      ev.get("ts_fin","") or ev.get("ts_inicio",""),
            }
        grupos[key]["ocurrencias"].append({
            "inicio": ev.get("ts_inicio",""),
            "fin":    ev.get("ts_fin",""),
            "dur":    ev.get("duracion",""),
        })
        # Actualizar primera y ultima
        ts_i = ev.get("ts_inicio","")
        ts_f = ev.get("ts_fin","") or ts_i
        if ts_i and (not grupos[key]["primera"] or ts_i < grupos[key]["primera"]):
            grupos[key]["primera"] = ts_i
        if ts_f and ts_f > grupos[key]["ultima"]:
            grupos[key]["ultima"] = ts_f
    # Marcar como activo si coincide con alarma activa actual
    rt = load_alertas_rt()
    activas_rt = {(a.get("router",""), a.get("tipo",""), a.get("ifname",""))
                  for a in rt.get("alarmas",[]) if a.get("activa")}
    for ev in grupos.values():
        key = (ev["router"], ev["tipo"], ev.get("ifname",""))
        ev["activa_ahora"] = key in activas_rt
    # Ordenar por ultima ocurrencia desc
    eventos_agrupados = sorted(grupos.values(), key=lambda x: x["ultima"], reverse=True)
    # Separar activas y resueltas
    solo_resueltas = [e for e in eventos_agrupados if not e.get("activa_ahora")]
    return jsonify({"ok":True,"fecha":h.get("fecha"),"eventos":solo_resueltas,"total_raw":len(eventos_48h)})

# ---------------------------------------------------------------------------
# SILENCIOS GRAFANA (solo admin)
# ---------------------------------------------------------------------------

CATALOGO_CACHE_FILE = os.path.join(DATA_DIR, "catalogo_grafana_cache.json")

def grafana_get_catalogo_reglas():
    """Obtiene TODAS las reglas de alerta configuradas en Grafana dentro de las
    carpetas CLLANOS/MPLS-ISP, esten o no disparadas actualmente. Cachea 1 hora."""
    try:
        cache = load_json(CATALOGO_CACHE_FILE, {})
        if cache.get("ts"):
            ts = datetime.strptime(cache["ts"], "%d/%m/%Y %H:%M")
            if (datetime.now() - ts).total_seconds() < 3600:
                return cache.get("reglas", [])
    except Exception:
        pass

    headers = {"Authorization": f"Bearer {GRAFANA_TOKEN}"}
    try:
        r = req.get(f"{GRAFANA_URL}/api/v1/provisioning/alert-rules",
                    headers=headers, timeout=30, verify=False)
        reglas_raw = r.json()
    except Exception as e:
        print(f"[Catalogo Grafana] Error obteniendo reglas: {e}")
        return []

    folder_uids = list(set([rr.get("folderUID","") for rr in reglas_raw if rr.get("folderUID")]))
    folder_info = {}
    for fuid in folder_uids:
        try:
            rf = req.get(f"{GRAFANA_URL}/api/folders/{fuid}",
                         headers=headers, timeout=15, verify=False)
            if rf.status_code == 200:
                folder_info[fuid] = rf.json()
        except Exception:
            continue

    def folder_es_nuestro(fuid):
        info = folder_info.get(fuid, {})
        titles = [info.get("title","")] + [p.get("title","") for p in info.get("parents",[])]
        return any("CLLANOS" in t for t in titles)

    resultado = []
    for rr in reglas_raw:
        fuid = rr.get("folderUID","")
        if not folder_es_nuestro(fuid):
            continue
        nombre = rr.get("title","")
        folder_path = " / ".join(
            [p.get("title","") for p in folder_info.get(fuid,{}).get("parents",[])] +
            [folder_info.get(fuid,{}).get("title","")]
        )
        tipo, sev, categoria = clasificar_alerta_grafana(nombre, folder_path)
        if categoria is None:
            continue
        resultado.append({
            "uid":       rr.get("uid",""),
            "nombre":    nombre,
            "categoria": categoria,
            "tipo":      tipo,
            "pausada":   rr.get("isPaused", False),
            "folder":    folder_path,
        })

    resultado.sort(key=lambda x: (x["categoria"], x["nombre"]))
    save_json(CATALOGO_CACHE_FILE, {"ts": ahora_str(), "reglas": resultado})
    return resultado

@app.route("/api/grafana/catalogo", methods=["GET"])
@login_required
def get_catalogo_grafana():
    """Lista TODAS las reglas configuradas (disparadas o no) para visibilidad total."""
    reglas = grafana_get_catalogo_reglas()
    # Marcar cuales estan actualmente activas
    try:
        activas_raw = grafana_get_alertas_raw()
        uids_activos = set(a.get("alert_uid","") for a in activas_raw)
    except Exception:
        uids_activos = set()
    for r in reglas:
        r["disparada"] = r["uid"] in uids_activos
    return jsonify({"ok": True, "total": len(reglas), "reglas": reglas})

@app.route("/api/grafana/silencios", methods=["GET"])
@login_required
def get_silencios():
    """Retorna lista de alertas Grafana con estado de silencio."""
    silencios = load_silencios()
    now = datetime.now()
    # Obtener alertas actuales de Grafana para listarlas
    try:
        alertas = grafana_get_alertas_raw()
    except Exception:
        alertas = []

    # Agrupar por alertname unico
    visto = {}
    for a in alertas:
        nombre  = a.get("alertname","")
        uid     = a.get("alert_uid","") or nombre
        if uid not in visto:
            s = silencios.get(uid, {})
            activo = False
            hasta_str = ""
            if s.get("indefinido"):
                activo = True; hasta_str = "Indefinido"
            elif s.get("hasta"):
                try:
                    dt = datetime.strptime(s["hasta"], "%d/%m/%Y %H:%M")
                    if now < dt:
                        activo = True; hasta_str = s["hasta"]
                    else:
                        del silencios[uid]; save_silencios(silencios)
                except Exception:
                    pass
            visto[uid] = {
                "uid":    uid,
                "label":  nombre,
                "activo": activo,
                "hasta":  hasta_str,
                "cat":    a.get("categoria",""),
            }

    # Agregar silencios guardados que ya no estan activos en Grafana
    result = list(visto.values())
    return jsonify({"ok": True, "silencios": result})

@app.route("/api/grafana/silencios/<path:uid>", methods=["POST"])
@login_required
def set_silencio(uid):
    """Activa o desactiva silencio de una alerta especifica. Solo admin."""
    if session.get("role") != "admin" and session.get("user") not in ("cllanos","admin"):
        return jsonify({"ok": False, "error": "Solo admin"}), 403
    data = request.get_json() or {}
    accion   = data.get("accion", "activar")
    duracion = data.get("duracion", 4)
    silencios = load_silencios()
    if accion == "desactivar":
        silencios.pop(uid, None)
        save_silencios(silencios)
        return jsonify({"ok": True, "msg": "Alerta reactivada"})
    else:
        import datetime as dt_mod
        if duracion == 0:
            silencios[uid] = {"indefinido": True, "activado": ahora_str()}
        else:
            hasta = datetime.now() + dt_mod.timedelta(hours=int(duracion))
            silencios[uid] = {"hasta": hasta.strftime("%d/%m/%Y %H:%M"), "activado": ahora_str()}
        save_silencios(silencios)
        return jsonify({"ok": True, "msg": "Alerta silenciada"})

@app.route("/api/trafico/historial/delete", methods=["POST"])
@login_required
def delete_historial_event():
    """Elimina un evento del historial por indice."""
    idx = request.json.get("index")
    if idx is None:
        return jsonify({"ok":False,"error":"index requerido"})
    h = load_hist()
    evs = h.get("eventos",[])
    if 0 <= idx < len(evs):
        eliminado = evs.pop(idx)
        save_json(ALERTAS_HIST, h)
        return jsonify({"ok":True,"eliminado":eliminado["router"]})
    return jsonify({"ok":False,"error":"indice invalido"})

@app.route("/api/trafico/historial/clear", methods=["POST"])
@login_required
def clear_historial():
    """Limpia todo el historial."""
    save_json(ALERTAS_HIST, {"fecha": date.today().strftime("%d/%m/%Y"), "eventos":[]})
    return jsonify({"ok":True})

@app.route("/api/trafico/<devif>")
@login_required
def trafico_devif(devif):
    """Historico de trafico de una interfaz desde InfluxDB para graficos."""
    ifname  = request.args.get("ifname","")
    rango   = request.args.get("rango","24h")
    if rango not in ["24h","48h","7d"]:
        rango = "24h"
    ventana = {"24h":"24h","48h":"48h","7d":"168h"}.get(rango,"24h")
    pts     = influx_get_historico_devif(devif, ifname, ventana)
    return jsonify({"ok":True,"devif":devif,"ifname":ifname,"rango":rango,"points":pts})

@app.route("/api/trafico/forzar_poll", methods=["POST"])
@login_required
def forzar_poll():
    threading.Thread(target=ejecutar_polling, daemon=True).start()
    return jsonify({"ok":True,"msg":"Polling iniciado"})

@app.route("/api/trafico/actualizar_cache", methods=["POST"])
@admin_required
def actualizar_cache_ep():
    threading.Thread(target=actualizar_cache, daemon=True).start()
    return jsonify({"ok":True,"msg":"Cache actualizandose"})

@app.route("/api/trafico/anomalias_por_grupo")
@login_required
def anomalias_por_grupo():
    rt      = load_alertas_rt()
    alarmas = rt.get("alarmas",[])
    cache   = load_json(CACHE_FILE, {})
    rol_map = {r.get("name",""): r.get("rol","") for r in cache.get("routers",[])}
    por_seccion = {}
    for a in alarmas:
        nombre = a["router"].split(" (")[0].strip()
        rol    = rol_map.get(nombre,"")
        sec    = 1 if rol=="router-p" else 2
        por_seccion.setdefault(sec,[]).append(a)
    return jsonify({"ok":True,"por_seccion":por_seccion})

@app.route("/api/alarmas/ack", methods=["POST"])
@login_required
def ack_alarma():
    data  = request.json or {}
    acks  = load_ack()
    hoy   = date.today().strftime("%d/%m/%Y")
    nueva = {**data,"fecha":hoy,"ack_at":ahora_str(),"ack_by":session.get("user","")}
    acks  = [a for a in acks if not (
        a["router"]==nueva.get("router") and a["tipo"]==nueva.get("tipo") and
        a.get("ifname","")==nueva.get("ifname","") and a["fecha"]==hoy)]
    acks.insert(0, nueva)
    save_ack(acks[:500])
    return jsonify({"ok":True})

@app.route("/api/alarmas/ack/all", methods=["POST"])
@login_required
def ack_todas():
    data    = request.json or {}
    alarmas = data.get("alarmas",[])
    acks    = load_ack()
    hoy     = date.today().strftime("%d/%m/%Y")
    ahora   = ahora_str()
    usuario = session.get("user","")
    for a in alarmas:
        ya = any(x["router"]==a["router"] and x["tipo"]==a["tipo"] and
                 x.get("ifname","")==a.get("ifname","") and x["fecha"]==hoy for x in acks)
        if not ya:
            acks.insert(0,{**a,"fecha":hoy,"ack_at":ahora,"ack_by":usuario})
    save_ack(acks[:500])
    return jsonify({"ok":True})

@app.route("/api/alarmas/ack/reset", methods=["POST"])
@login_required
def reset_acks():
    hoy = date.today().strftime("%d/%m/%Y")
    save_ack([a for a in load_ack() if a.get("fecha")!=hoy])
    return jsonify({"ok":True})

@app.route("/api/alarmas/ack", methods=["GET"])
@login_required
def get_acks():
    return jsonify({"ok":True,"acks":load_ack()})

@app.route("/api/mat/notificar", methods=["POST"])
@login_required
def mat_notificar():
    try:
        d         = request.get_json() or {}
        ingeniero = d.get("ingeniero", "GOC")
        turno     = d.get("turno", "")
        secciones = d.get("secciones", [])
        eventos   = d.get("eventos", [])

        # Si no vienen eventos, usar historial del dia
        if not eventos:
            h = load_hist()
            eventos = h.get("eventos", [])

        html_reporte = d.get("html_reporte", None)
        print("[Reporte] html_reporte recibido:", bool(html_reporte), "len:", len(html_reporte) if html_reporte else 0, "payload total:", len(str(d)), "content_type:", request.content_type)
        ok, status, resp = enviar_correo_mat(
            eventos, turno, ingeniero,
            date.today().strftime("%d/%m/%Y"),
            secciones=secciones,
            html_reporte=html_reporte)
        return jsonify({"ok":ok,"status":status,"resp":resp})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e)}), 500

@app.route("/api/revisiones")
@login_required
def get_revisiones():
    return jsonify({"ok":True,"revisiones":load_revisiones()})

@app.route("/api/revisiones", methods=["POST"])
@login_required
def save_revision():
    data  = request.json or {}
    revs  = load_revisiones()
    secs  = data.get("secciones",[])
    nueva = {
        "id":          len(revs)+1,
        "fecha":       date.today().strftime("%d/%m/%Y"),
        "hora":        datetime.now().strftime("%H:%M"),
        "turno":       data.get("turno","AM"),
        "ingeniero":   data.get("ingeniero",session.get("user","")),
        "secundario":  data.get("secundario",""),
        "secciones":   secs,
        "anomalias":   data.get("anomalias",[]),
        "eventos":     data.get("eventos",[]),
        "ts":          datetime.now().strftime("%d/%m/%Y %H:%M"),
        "obs_general": data.get("obs_general",""),
        "resumen": {
            "total":       data.get("total_secciones",0),
            "completadas": data.get("completadas",0),
            "con_novedad": len([s for s in secs if s.get("estado")=="novedad"]),
            "con_falla":   len([s for s in secs if s.get("estado")=="falla"]),
        },
        "guardado_por": session.get("user",""),
        "guardado_en":  ahora_str(),
    }
    revs.insert(0, nueva)
    save_revisiones(revs[:500])
    return jsonify({"ok":True,"id":nueva["id"]})

@app.route("/api/revisiones/<int:rev_id>")
@login_required
def get_revision(rev_id):
    rev = next((r for r in load_revisiones() if r["id"]==rev_id), None)
    if not rev:
        return jsonify({"error":"not found"}), 404
    return jsonify(rev)

@app.route("/api/config")
@login_required
def get_config():
    return jsonify(load_config())

@app.route("/api/config", methods=["POST"])
@admin_required
def update_config():
    save_json(CONFIG_FILE, request.json)
    return jsonify({"ok":True})



@app.route("/api/admin/usuarios", methods=["GET"])
@admin_required
def get_usuarios():
    users = load_users()
    result = [{"username": u, "role": d["role"], "activo": d.get("activo", True)} for u, d in users.items()]
    return jsonify({"ok": True, "usuarios": result})

@app.route("/api/admin/usuarios", methods=["POST"])
@admin_required
def add_usuario():
    data = request.get_json() or {}
    username = data.get("username","").strip()
    password = data.get("password","").strip()
    role     = data.get("role", "viewer")
    if not username or not password:
        return jsonify({"ok": False, "error": "username y password requeridos"})
    if role not in ("admin", "viewer"):
        return jsonify({"ok": False, "error": "role invalido"})
    users = load_users()
    if username in users:
        return jsonify({"ok": False, "error": "Usuario ya existe"})
    users[username] = {"password": password, "role": role, "activo": True}
    save_users(users)
    return jsonify({"ok": True, "msg": f"Usuario {username} creado"})

@app.route("/api/admin/usuarios/<username>", methods=["DELETE"])
@admin_required
def delete_usuario(username):
    if username in ("admin", "cllanos"):
        return jsonify({"ok": False, "error": "No se puede eliminar este usuario"})
    users = load_users()
    if username not in users:
        return jsonify({"ok": False, "error": "Usuario no existe"})
    del users[username]
    save_users(users)
    return jsonify({"ok": True, "msg": f"Usuario {username} eliminado"})

@app.route("/api/admin/usuarios/<username>/toggle", methods=["POST"])
@admin_required
def toggle_usuario(username):
    if username in ("admin", "cllanos"):
        return jsonify({"ok": False, "error": "No se puede pausar este usuario"})
    users = load_users()
    if username not in users:
        return jsonify({"ok": False, "error": "Usuario no existe"})
    users[username]["activo"] = not users[username].get("activo", True)
    save_users(users)
    estado = "activado" if users[username]["activo"] else "pausado"
    return jsonify({"ok": True, "msg": f"Usuario {username} {estado}"})

@app.route("/api/admin/usuarios/<username>/password", methods=["POST"])
@admin_required
def change_password(username):
    data = request.get_json() or {}
    pwd = data.get("password","").strip()
    if not pwd:
        return jsonify({"ok": False, "error": "password requerido"})
    users = load_users()
    if username not in users:
        return jsonify({"ok": False, "error": "Usuario no existe"})
    users[username]["password"] = pwd
    save_users(users)
    return jsonify({"ok": True, "msg": "Password actualizado"})

# ============ GESTION CORREOS ============
@app.route("/api/admin/correos", methods=["GET"])
@admin_required
def get_correos():
    return jsonify({"ok": True, "correos": load_correos()})

@app.route("/api/admin/correos", methods=["POST"])
@admin_required
def add_correo():
    data = request.get_json() or {}
    email = data.get("email","").strip()
    if not email or "@" not in email:
        return jsonify({"ok": False, "error": "email invalido"})
    correos = load_correos()
    if email in correos:
        return jsonify({"ok": False, "error": "Email ya existe"})
    correos.append(email)
    save_correos(correos)
    return jsonify({"ok": True, "msg": f"{email} agregado"})

@app.route("/api/admin/correos/<path:email>", methods=["DELETE"])
@admin_required
def delete_correo(email):
    correos = load_correos()
    if email not in correos:
        return jsonify({"ok": False, "error": "Email no existe"})
    correos.remove(email)
    save_correos(correos)
    return jsonify({"ok": True, "msg": f"{email} eliminado"})



# ============ CHATBOT OLLAMA ============
OLLAMA_URL   = "http://10.68.12.190:11434"
OLLAMA_MODEL = "qwen2.5-coder:14b"


def chat_get_devnames_influx():
    cache_file = os.path.join(DATA_DIR, "cache_devnames_influx.json")
    try:
        c = load_json(cache_file, {})
        if c.get("ts") and c.get("devnames"):
            import datetime as _dt
            ts = _dt.datetime.strptime(c["ts"], "%d/%m/%Y %H:%M")
            if (_dt.datetime.now() - ts).seconds < 3600:
                return c["devnames"]
    except:
        pass
    try:
        q = ('SELECT last("ifHCInOctets") FROM "trafico"'
             ' WHERE "ifAlias" =~ /(' + DESC_REGEX + ')/'
             ' AND time > now()-30m'
             ' GROUP BY "devname" LIMIT 1')
        data = influx_query(q, timeout=30)
        series = data.get("results",[{}])[0].get("series",[])
        devnames = sorted(list(set([s.get("tags",{}).get("devname","") for s in series if s.get("tags",{}).get("devname")])))
        save_json(cache_file, {"ts": ahora_str(), "devnames": devnames})
        print("[Chat] Devnames cacheados:", len(devnames))
        return devnames
    except Exception as e:
        print("[Chat devnames] Error:", e)
        return []

def buscar_devname_real(nombre_usuario, devnames_reales):
    """Mapea nombre escrito por usuario al devname real en InfluxDB."""
    if not nombre_usuario or not devnames_reales:
        return None
    sufijos = ['.vtr.cl', '.clarochile.cl', '.telmex.cl', '.claro.cl']
    def limpiar(s):
        s = s.lower()
        for sf in sufijos:
            s = s.replace(sf, '')
        return s
    nombre_clean = limpiar(nombre_usuario)
    # 1. Coincidencia exacta sin sufijos
    for d in devnames_reales:
        if limpiar(d) == nombre_clean:
            return d
    # 2. El nombre del usuario esta contenido en el devname real
    for d in devnames_reales:
        if nombre_clean in limpiar(d):
            return d
    # 3. El devname real esta contenido en el nombre del usuario
    for d in devnames_reales:
        if limpiar(d) in nombre_clean:
            return d
    # 4. Match parcial por palabras clave
    palabras = [p for p in nombre_clean.replace('_','-').split('-') if len(p)>2]
    for d in devnames_reales:
        d_clean = limpiar(d)
        if all(p in d_clean for p in palabras):
            return d
    return None


NETWORK_API_URL   = "http://10.68.12.20:8080/network-api/devices"
NETWORK_API_CACHE = os.path.join(DATA_DIR, "cache_network_api.json")

def get_network_devices():
    try:
        c = load_json(NETWORK_API_CACHE, {})
        if c.get("ts") and c.get("devices"):
            import datetime as _dt
            ts = _dt.datetime.strptime(c["ts"], "%d/%m/%Y %H:%M")
            if (_dt.datetime.now() - ts).total_seconds() < 3600:
                return c["devices"]
    except:
        pass
    try:
        import urllib.request as _ur
        r = _ur.urlopen(NETWORK_API_URL, timeout=10)
        import json as _json
        data = _json.loads(r.read().decode())
        devices = [d for d in data.get("data", []) if d.get("area") == "NTWKBB"]
        save_json(NETWORK_API_CACHE, {"ts": ahora_str(), "devices": devices})
        print("[NetworkAPI] Dispositivos cacheados:", len(devices))
        return devices
    except Exception as e:
        print("[NetworkAPI] Error:", e)
        return []

def buscar_devnames_por_ciudad_operador(ciudades, operador=None):
    devices = get_network_devices()
    resultado = {}
    for ciudad_u in ciudades:
        ciudad_clean = ciudad_u.upper().strip()
        matches = []
        for d in devices:
            hub   = d.get("hub", "").upper()
            dname = d.get("devname", "")
            op    = d.get("operador", "")
            # Mapeo especial de ciudades a hubs
            hub_map = {
                "PUERTO MONTT": "PMON", "PUERTO MONTT": "PMON",
                "VINA DEL MAR": "VINA", "LA SERENA": "LSER",
                "LOS ANGELES": "LANG", "SAN FERNANDO": "SANF",
                "PUNTA ARENAS": "PAR", "LAS CONDES": "LCON",
                "CONCEPCION": "CONC", "TALCAHUANO": "TALC",
                "ANTOFAGASTA": "ANTO", "VALPARAISO": "QOTA",
            }
            # Usar CIUDAD_HUB_MAP para obtener hub correcto
            ciudad_lower = ciudad_clean.lower()
            hub_desde_mapa = CIUDAD_HUB_MAP.get(ciudad_lower, "")
            hub_esperado = hub_map.get(ciudad_clean, hub_desde_mapa or ciudad_clean[:4])
            ciudad_match = (ciudad_clean in hub or hub_esperado in hub or hub in ciudad_clean)
            if not ciudad_match:
                continue
            if operador:
                op_clean = operador.upper()
                if op_clean == "VTR" and op != "exVTR":
                    continue
                if op_clean == "CLARO" and op != "exCLARO":
                    continue
            if dname:
                matches.append(dname)
        if matches:
            resultado[ciudad_u] = matches
    return resultado

def chat_query_influx_ciudades(ciudades_devnames, ventana="5m", intencion=None):
    try:
        devnames_reales = chat_get_devnames_influx()
        resultado = {}
        for ciudad, devnames in ciudades_devnames.items():
            total_in = 0.0
            total_out = 0.0
            interfaces = []
            for devname in devnames:
                # Primero verificar si el devname ya existe exactamente en InfluxDB
                if devname in devnames_reales:
                    devname_real = devname
                else:
                    devname_real = buscar_devname_real(devname, devnames_reales)
                if not devname_real:
                    continue
                metrica = intencion.get("metrica", "trafico") if isinstance(intencion, dict) else "trafico"
                descriptor = intencion.get("descriptor", "bbuplink") if isinstance(intencion, dict) else "bbuplink"
                if descriptor == "bbdrpup":
                    desc_regex_q = "BBDRPUP"
                else:
                    desc_regex_q = DESC_REGEX
                if metrica == "capacidad":
                    q = ("SELECT last(\"ifSpeed\") AS speed"
                         " FROM \"trafico\""
                         " WHERE \"devname\" = '" + devname_real + "'"
                         " AND \"ifAlias\" =~ /(" + desc_regex_q + ")/"
                         " AND time > now()-30m"
                         " GROUP BY \"ifName\",\"ifAlias\"")
                elif metrica == "estado":
                    q = ("SELECT last(\"ifHCInOctets\") AS in_bytes,"
                         " last(\"ifOper\") AS oper,"
                         " last(\"ifSpeed\") AS speed"
                         " FROM \"trafico\""
                         " WHERE \"devname\" = '" + devname_real + "'"
                         " AND \"ifAlias\" =~ /(" + desc_regex_q + ")/"
                         " AND time > now()-10m"
                         " GROUP BY \"ifName\",\"ifAlias\"")
                elif metrica == "errores":
                    q = ("SELECT non_negative_derivative(mean(\"ifInErrors\"),1s) AS in_err,"
                         " non_negative_derivative(mean(\"ifOutErrors\"),1s) AS out_err"
                         " FROM \"trafico\""
                         " WHERE \"devname\" = '" + devname_real + "'"
                         " AND \"ifAlias\" =~ /(" + desc_regex_q + ")/"
                         " AND time > now()-" + ventana +
                         " GROUP BY time(100s),\"ifName\",\"ifAlias\" fill(null)")
                elif metrica == "descartes":
                    q = ("SELECT non_negative_derivative(mean(\"ifInDiscards\"),1s) AS in_dis,"
                         " non_negative_derivative(mean(\"ifOutDiscards\"),1s) AS out_dis"
                         " FROM \"trafico\""
                         " WHERE \"devname\" = '" + devname_real + "'"
                         " AND \"ifAlias\" =~ /(" + desc_regex_q + ")/"
                         " AND time > now()-" + ventana +
                         " GROUP BY time(100s),\"ifName\",\"ifAlias\" fill(null)")
                else:
                    q = ("SELECT non_negative_derivative(mean(\"ifHCInOctets\"),1s)*8 AS in_bps,"
                         " non_negative_derivative(mean(\"ifHCOutOctets\"),1s)*8 AS out_bps,"
                         " last(\"ifSpeed\") AS speed"
                         " FROM \"trafico\""
                         " WHERE \"devname\" = '" + devname_real + "'"
                         " AND \"ifAlias\" =~ /(" + desc_regex_q + ")/"
                         " AND time > now()-" + ventana +
                         " GROUP BY time(100s),\"ifName\",\"ifAlias\" fill(null)")
                data = influx_query(q, timeout=20)
                series = data.get("results",[{}])[0].get("series",[])
                for s in series:
                    vals = s.get("values",[])
                    ifname  = s.get("tags",{}).get("ifName","")
                    ifalias = s.get("tags",{}).get("ifAlias","")
                    if "." in ifname:
                        continue
                    if descriptor == "bbdrpup":
                        if "BBDRPUP" not in ifalias:
                            continue
                        # Para DRP usar solo fisicas (TenGigE, GigabitEthernet, etc)
                        if not es_fisica(ifname):
                            continue
                    else:
                        if "BBUPLINK" not in ifalias:
                            continue
                        # Para BBUPLINK usar solo bundles (Eth-Trunk, Bundle-Ether, ae)
                        # El bundle ya agrega todos los miembros fisicos - evita doble conteo
                        es_bundle = any(ifname.startswith(p) for p in ["Eth-Trunk","Bundle-Ether","ae"])
                        if not es_bundle:
                            continue
                    if metrica == "estado":
                        val_in = None
                        val_oper = None
                        val_speed = None
                        for row in vals:
                            if row[1] is not None: val_in = row[1]    # ifHCInOctets
                            if len(row)>2 and row[2] is not None: val_oper = row[2]  # ifOper
                            if len(row)>3 and row[3] is not None: val_speed = row[3] # ifSpeed
                        # ifHCInOctets > 0 = UP (tiene trafico control OSPF)
                        # ifOper = 1 = UP segun SNMP
                        if val_in is not None and val_in > 0:
                            estado_str = "UP"
                        elif val_oper is not None and int(val_oper) == 1:
                            estado_str = "UP"
                        else:
                            estado_str = "DOWN"
                        speed_gbps = round(val_speed/1000,2) if val_speed else 0
                        total_in += 1 if estado_str == "UP" else 0
                        interfaces.append({
                            "devname": devname_real, "ifname": ifname,
                            "in_gbps": speed_gbps, "out_gbps": 0, "pct": 0,
                            "estado": estado_str
                        })
                        continue
                    elif metrica == "capacidad":
                        # Para capacidad usamos last(ifSpeed)
                        val_speed = None
                        for row in vals:
                            if row[1] is not None:
                                val_speed = row[1]
                        if val_speed is None:
                            continue
                        speed_gbps = round(val_speed / 1000, 1)  # ifSpeed: Mbps -> Gbps
                        total_in += val_speed * 1e6  # Mbps -> bps para acumular igual que trafico
                        interfaces.append({
                            "devname":  devname_real,
                            "ifname":   ifname,
                            "in_gbps":  speed_gbps,
                            "out_gbps": 0,
                            "pct":      0
                        })
                    elif metrica in ("errores", "descartes"):
                        vals_ok = [v for v in vals if v[1] is not None]
                        if not vals_ok: continue
                        v = vals_ok[-1]
                        in_val  = v[1] or 0
                        out_val = v[2] or 0 if len(v)>2 else 0
                        total_in  += in_val
                        total_out += out_val
                        interfaces.append({
                            "devname":  devname_real,
                            "ifname":   ifname,
                            "in_gbps":  round(in_val, 4),
                            "out_gbps": round(out_val, 4),
                            "pct":      0
                        })
                    else:
                        vals_ok = [v for v in vals if v[1] is not None]
                        if not vals_ok: continue
                        v = vals_ok[-1]
                        in_bps  = v[1] or 0
                        out_bps = v[2] or 0
                        speed_raw = v[3] if len(v)>3 and v[3] else 0
                        # ifSpeed viene en Mbps en InfluxDB
                        # ifSpeed en InfluxDB viene en Mbps
                        if speed_raw and speed_raw > 0:
                            speed = speed_raw * 1e6  # Mbps -> bps
                        elif "Bundle-Ether" in ifname or "Eth-Trunk" in ifname:
                            speed = 400e9
                        elif "HundredGig" in ifname or "100GE" in ifname:
                            speed = 100e9
                        elif "TenGig" in ifname or "10GE" in ifname or "xe-" in ifname or "et-" in ifname:
                            speed = 10e9
                        elif "GigabitEthernet" in ifname or "ge-" in ifname:
                            speed = 1e9
                        else:
                            speed = 10e9
                        total_in  += in_bps
                        total_out += out_bps
                        pct = round(in_bps/speed*100,1) if speed>0 else 0
                        interfaces.append({
                            "devname": devname_real,
                            "ifname":  ifname,
                            "in_gbps": round(in_bps/1e9,2),
                            "out_gbps":round(out_bps/1e9,2),
                            "pct":     pct
                        })
            resultado[ciudad] = {
                "total_in_gbps":  round(total_in/1e9,2),
                "total_out_gbps": round(total_out/1e9,2),
                "interfaces":     interfaces
            }
        return resultado
    except Exception as e:
        print("[Chat ciudades] Query error:", e)
        return {}


# Mapeo ciudad -> regex devname para filtrar routers ISP
CIUDAD_DEVNAME_MAP = {
    "la cisterna":   "LCIS",
    "cisterna":      "LCIS",
    "lcis":          "LCIS",
    "independencia": "INDE",
    "inde":          "INDE",
    "fanor":         "FNR",
    "fanorrama":     "FNR",
    "fnr":           "FNR",
    "santiago":      "SLT",
    "salto":         "SLT",
    "el salto":      "SLT",
    "vina":          "VINA",
    "valparaiso":    "VINA|QOTA",
    "antofagasta":   "ANTO",
    "rancagua":      "RANC",
    "concepcion":    "CONC",
    "talca":         "TALC",
    "temuco":        "TEMU",
    "osorno":        "OSOR",
    "iquique":       "IQUI",
    "la serena":     "LSER",
    "serena":        "LSER",
}

CIUDAD_HUB_MAP = {
    "antofagasta": "ANTO", "arica": "ARIC", "calama": "CALA",
    "chillan": "CHIL", "concepcion": "CONC", "constitucion": "CONS",
    "copiapo": "COPI", "curico": "CURI", "independencia": "INDE",
    "iquique": "IQUI", "la serena": "LSER", "las condes": "LCON",
    "linares": "LINA", "los angeles": "LANG", "los flores": "LFLO",
    "maipu": "MAIP", "nunoa": "NUN", "osorno": "OSOR",
    "parral": "PARR", "punta arenas": "PAR", "puerto montt": "PMON",
    "quilicura": "QUIL", "quilpue": "QOTA", "quinta normal": "QNOR",
    "rancagua": "RANC", "san fernando": "SANF", "san antonio": "SANT",
    "santiago": "SLT", "el salto": "SLT", "salto": "SLT", "talca": "TALC", "talcahuano": "TALC",
    "temuco": "TEMU", "valdivia": "VALD", "valparaiso": "VPS",
    "vina del mar": "VINA", "vina": "VINA", "los andes": "LAND",
    "angol": "ANGL", "serena": "LSER",
}

def detectar_intencion_python(pregunta):
    import re as _re
    p = pregunta.lower()
    # Metrica - detectar si pide multiples metricas
    pide_trafico = any(x in p for x in ["trafico", "tráfico"])
    pide_capacidad = any(x in p for x in ["capacidad", "cap"])
    if pide_trafico and pide_capacidad:
        metrica = "trafico_y_capacidad"
    elif pide_capacidad:
        metrica = "capacidad"
    elif any(x in p for x in ["error"]):
        metrica = "errores"
    elif any(x in p for x in ["discard", "descarte"]):
        metrica = "descartes"
    elif any(x in p for x in ["operativ", "esta up", "esta down", "estan up", "estan down", "estado de"]):
        metrica = "estado"
    else:
        metrica = "trafico"
    # Descriptor - detectar proveedor ISP
    descriptor = "bbdrpup" if "drp" in p else "bbuplink"
    # Buscar si menciona un proveedor ISP
    proveedor_isp = None
    filtro_devname_isp = None
    for prov, desc_isp in PROVEEDOR_DESCRIPTOR_MAP.items():
        if prov in p:
            proveedor_isp = desc_isp
            descriptor = "isp_proveedor"
            break
    # Buscar ciudad para filtrar routers ISP
    if proveedor_isp:
        for ciudad, regex in CIUDAD_DEVNAME_MAP.items():
            if ciudad in p:
                filtro_devname_isp = regex
                break
    # Operador - detectar uno o ambos
    tiene_claro = "claro" in p
    tiene_vtr = "vtr" in p
    if tiene_claro and tiene_vtr:
        operador = "AMBOS"
    elif tiene_claro:
        operador = "CLARO"
    elif tiene_vtr:
        operador = "VTR"
    else:
        operador = None
    # Umbral
    um = _re.search(r'(\d+)\s*%', pregunta)
    umbral_pct = int(um.group(1)) if um else None
    # Ciudades
    ciudades = []
    hubs_vistos = set()
    for ciudad, hub in CIUDAD_HUB_MAP.items():
        if ciudad in p and hub not in hubs_vistos:
            ciudades.append(ciudad.upper())
            hubs_vistos.add(hub)
    # Devname - patron router
    devname = None
    dm = _re.search(r'\b([A-Z]{2,8}[_\-][A-Z0-9]{2,8}[_\-][A-Z0-9]{2,12})\b', pregunta)
    if dm:
        devname = dm.group(1)
    # Ventana
    if "24h" in p or "ayer" in p:
        ventana = "24h"
    elif "1h" in p:
        ventana = "1h"
    else:
        ventana = "5m"
    # Necesita trafico
    necesita = bool(ciudades or devname or
        any(x in p for x in ["%", "trafico", "capacidad", "saturad",
            "utilizaci", "gbps", "mbps", "drp", "enlace", "operativ",
            "error", "descarte", "discard", "trafico"]))
    return {
        "necesita_trafico": necesita,
        "metrica": metrica,
        "descriptor": descriptor,
        "operador": operador,
        "ciudades": ciudades,
        "devname": devname,
        "ventana": ventana,
        "umbral_pct": umbral_pct,
        "proveedor_isp": proveedor_isp if 'proveedor_isp' in dir() else None,
        "filtro_devname_isp": filtro_devname_isp if 'filtro_devname_isp' in dir() else None,
        "tipo": "ciudades" if ciudades else ("interfaz_especifica" if devname else "top_trafico"),
    }



def chat_query_isp_proveedor(descriptor_isp, metrica="trafico", ventana="5m", filtro_devname=None):
    """Consulta trafico o capacidad de un proveedor ISP por descriptor ifAlias."""
    try:
        alias_regex = descriptor_isp.replace("_", "[_]?")
        devname_filter = ""
        if filtro_devname:
            devname_filter = " AND \"devname\" =~ /" + filtro_devname + "/"
        if metrica == "capacidad":
            q = ("SELECT last(\"ifSpeed\") AS speed"
                 " FROM \"trafico\""
                 " WHERE \"ifAlias\" =~ /" + alias_regex + "/"
                 + devname_filter +
                 " AND time > now()-30m"
                 " GROUP BY \"devname\",\"ifName\"")
        else:
            q = ("SELECT non_negative_derivative(mean(\"ifHCInOctets\"),1s)*8 AS in_bps,"
                 " non_negative_derivative(mean(\"ifHCOutOctets\"),1s)*8 AS out_bps"
                 " FROM \"trafico\""
                 " WHERE \"ifAlias\" =~ /" + alias_regex + "/"
                 + devname_filter +
                 " AND time > now()-" + ventana +
                 " GROUP BY time(100s),\"devname\",\"ifName\" fill(null)")
        data = influx_query(q, timeout=20)
        series = data.get("results",[{}])[0].get("series",[])
        resultados = []
        total_in = 0
        for s in series:
            tags = s.get("tags",{})
            ifname = tags.get("ifName","")
            if "." in ifname:
                continue
            # Solo bundles principales
            es_bundle = any(ifname.startswith(p) for p in ["Bundle-Ether","Eth-Trunk","ae","po","Po","port-channel"])
            if not es_bundle:
                continue
            vals = [v for v in s.get("values",[]) if v[1] is not None]
            if not vals:
                continue
            v = vals[-1]
            if metrica == "capacidad":
                speed = (v[1] or 0) / 1000
                resultados.append({
                    "devname": tags.get("devname",""),
                    "ifname":  ifname,
                    "cap_gbps": round(speed, 1),
                })
                total_in += speed
            else:
                in_bps  = v[1] or 0
                out_bps = v[2] or 0 if len(v)>2 else 0
                resultados.append({
                    "devname":  tags.get("devname",""),
                    "ifname":   ifname,
                    "in_gbps":  round(in_bps/1e9, 3),
                    "out_gbps": round(out_bps/1e9, 3),
                })
                total_in += in_bps/1e9
        resultados.sort(key=lambda x: x.get("in_gbps",x.get("cap_gbps",0)), reverse=True)
        return resultados, round(total_in, 2)
    except Exception as e:
        print("[ISP] Error:", e)
        return [], 0

def chat_query_drp_todos(operador=None, ventana="5m"):
    try:
        op_filter = ""
        if operador:
            op_key = "exVTR" if operador.upper() == "VTR" else "exCLARO"
            op_filter = " AND \"operador\" = '" + op_key + "'"
        q = ("SELECT last(\"ifHCInOctets\") AS in_bytes,"
             " last(\"ifHCOutOctets\") AS out_bytes,"
             " last(\"ifOper\") AS oper,"
             " last(\"ifSpeed\") AS speed"
             " FROM \"trafico\""
             " WHERE \"ifAlias\" =~ /BBDRPUP/"
             " AND \"iftype\" = '161'"
             + op_filter +
             " AND time > now()-30m"
             " GROUP BY \"devname\",\"ifName\"")
        # Query de trafico actual
        q_trafico = ("SELECT non_negative_derivative(mean(\"ifHCInOctets\"),1s)*8 AS in_bps,"
                     " non_negative_derivative(mean(\"ifHCOutOctets\"),1s)*8 AS out_bps"
                     " FROM \"trafico\""
                     " WHERE \"ifAlias\" =~ /BBDRPUP/"
                     " AND \"iftype\" = '161'"
                     + op_filter +
                     " AND time > now()-10m"
                     " GROUP BY time(100s),\"devname\",\"ifName\" fill(null)")
        data_t = influx_query(q_trafico, timeout=30)
        trafico_map = {}
        for s in data_t.get("results",[{}])[0].get("series",[]):
            tags_t = s.get("tags",{})
            key = tags_t.get("devname","") + "|" + tags_t.get("ifName","")
            vals_t = [v for v in s.get("values",[]) if v[1] is not None]
            if vals_t:
                v_t = vals_t[-1]
                trafico_map[key] = {
                    "in_bps": v_t[1] or 0,
                    "out_bps": v_t[2] or 0 if len(v_t)>2 else 0
                }
        data = influx_query(q, timeout=30)
        series = data.get("results",[{}])[0].get("series",[])
        resultados = []
        for s in series:
            tags = s.get("tags",{})
            ifname = tags.get("ifName","")
            vals = s.get("values",[])
            if not vals: continue
            v = vals[-1]
            in_bytes  = v[1] or 0
            out_bytes = v[2] or 0
            oper      = v[3] if len(v)>3 else None
            speed_raw = v[4] if len(v)>4 and v[4] else 0
            speed_gbps = round(speed_raw/1000,1) if speed_raw else 0
            is_up = (oper == 1) or (in_bytes > 0)
            con_trafico = in_bytes > 1e10
            devname_r = tags.get("devname","")
            key_r = devname_r + "|" + ifname
            traf = trafico_map.get(key_r, {})
            in_gbps_real  = round(traf.get("in_bps",0)/1e9,3)
            out_gbps_real = round(traf.get("out_bps",0)/1e9,3)
            resultados.append({
                "devname":        devname_r,
                "ifname":         ifname,
                "in_gbps":        in_gbps_real,
                "out_gbps":       out_gbps_real,
                "speed_gbps":     speed_gbps,
                "is_up":          is_up,
                "con_trafico":    in_gbps_real > 0.001
            })
        resultados.sort(key=lambda x: x["in_gbps"], reverse=True)
        return resultados
    except Exception as e:
        print("[DRP todos] Error:", e)
        return []

def chat_analizar_intencion(pregunta):
    lista_ciudades = "ANGOL,ANTOFAGASTA,ARICA,CALAMA,CHILLAN,CONCEPCION,COPIAPO,CURICO,INDEPENDENCIA,IQUIQUE,LA SERENA,LAS CONDES,LINARES,LOS ANGELES,MAIPU,OSORNO,PARRAL,PUERTO MONTT,PUNTA ARENAS,RANCAGUA,SANTIAGO,TALCA,TALCAHUANO,TEMUCO,VALDIVIA,VALPARAISO,VINA DEL MAR"
    prompt = ("Analiza esta pregunta de un ingeniero de red GOC y responde SOLO con JSON valido sin explicacion ni markdown.\n"
              "Pregunta: " + pregunta + "\n\n"
              "Ciudades disponibles: " + lista_ciudades + "\n"
              "Operadores: VTR o CLARO (null si no se menciona)\n\n"
              "JSON requerido (sin texto adicional):\n"
              "{\"necesita_trafico\": true o false, "
              "\"tipo\": \"top_trafico\" o \"interfaz_especifica\" o \"historico\" o \"ciudades\" o null, "
              "\"devname\": \"nombre del router si se menciona o null\", "
              "\"ciudades\": [\"CIUDAD1\",\"CIUDAD2\"] o [], "
              "\"operador\": \"VTR\" o \"CLARO\" o null, "
              "\"metrica\": \"trafico\" o \"capacidad\" o \"errores\" o \"descartes\" (default trafico), "
              "\"ifname\": \"nombre de interfaz si se menciona o null\", "
              "\"ventana\": \"5m\" o \"1h\" o \"24h\"}")
    try:
        r = req.post(OLLAMA_URL + "/api/chat",
            json={"model": OLLAMA_MODEL, "stream": False,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=30)
        import json as _json
        texto = r.json().get("message", {}).get("content", "{}").strip()
        if "```" in texto:
            texto = texto.split("```")[1]
            if texto.startswith("json"): texto = texto[4:]
        return _json.loads(texto.strip())
    except Exception as e:
        print("[Chat intencion] Error:", e)
        return {"necesita_trafico": False, "tipo": None}

def chat_query_influx(intencion):
    try:
        routers_raw = load_json("/app/routers.json", [])
        if isinstance(routers_raw, dict):
            routers_raw = routers_raw.get("routers", [])
        devnames = [r.get("devname","") for r in routers_raw if r.get("devname")]
        dev_regex = "|".join(devnames)
        tipo       = intencion.get("tipo")
        ventana    = intencion.get("ventana") or "10m"
        devname_esp = intencion.get("devname")
        ifname_esp  = intencion.get("ifname")
        metrica_q = intencion.get("metrica","trafico") if intencion else "trafico"
        if tipo == "interfaz_especifica" and devname_esp:
            filtro_dev = devname_esp
            filtro_if  = " AND \"ifName\" = '" + ifname_esp + "'" if ifname_esp else ""
            if metrica_q == "capacidad":
                q = ("SELECT last(\"ifSpeed\") AS speed"
                     " FROM \"trafico\""
                     " WHERE \"devname\" = '" + filtro_dev + "'"
                     + filtro_if +
                     " AND \"ifAlias\" =~ /(" + DESC_REGEX + ")/"
                     " AND time > now()-30m"
                     " GROUP BY \"devname\",\"ifName\",\"ifAlias\"")
            else:
                q = ("SELECT non_negative_derivative(mean(\"ifHCInOctets\"),1s)*8 AS in_bps,"
                     " non_negative_derivative(mean(\"ifHCOutOctets\"),1s)*8 AS out_bps,"
                     " last(\"ifSpeed\") AS speed"
                     " FROM \"trafico\""
                     " WHERE \"devname\" = '" + filtro_dev + "'"
                     + filtro_if +
                     " AND \"ifAlias\" =~ /(" + DESC_REGEX + ")/"
                     " AND time > now()-" + ventana +
                     " GROUP BY time(100s),\"devname\",\"ifName\",\"ifAlias\" fill(null)")
        else:
            q = ("SELECT non_negative_derivative(mean(\"ifHCInOctets\"),1s)*8 AS in_bps,"
                 " non_negative_derivative(mean(\"ifHCOutOctets\"),1s)*8 AS out_bps,"
                 " last(\"ifSpeed\") AS speed"
                 " FROM \"trafico\""
                 " WHERE \"ifAlias\" =~ /(" + DESC_REGEX + ")/"
                 " AND \"devname\" =~ /(" + dev_regex + ")/"
                 " AND time > now()-" + ventana +
                 " GROUP BY time(100s),\"devname\",\"ifName\",\"ifAlias\" fill(null)")
        data   = influx_query(q, timeout=30)
        series = data.get("results",[{}])[0].get("series",[])
        result = []
        devname_ctx = devname_esp or ""
        for s in series:
            tags = s.get("tags",{})
            vals = [v for v in s.get("values",[]) if v[1] is not None]
            if not vals: continue
            v = vals[-1]
            in_bps  = v[1] or 0
            out_bps = v[2] or 0
            speed_raw = v[3] if len(v)>3 and v[3] else 0
            ifname_tag = tags.get("ifName","")
            # Estimar capacidad segun tipo de interfaz
            if speed_raw and speed_raw > 1e6:
                speed = speed_raw
            elif "Hundred" in ifname_tag:
                speed = 100e9
            elif "TenGig" in ifname_tag or "tengig" in ifname_tag.lower():
                speed = 10e9
            elif "Bundle" in ifname_tag or "bundle" in ifname_tag.lower():
                speed = 400e9
            elif "FortyGig" in ifname_tag:
                speed = 40e9
            else:
                speed = 10e9
            pct_in  = round(in_bps/speed*100,1) if speed>0 else 0
            pct_out = round(out_bps/speed*100,1) if speed>0 else 0
            devname_tag = tags.get("devname","") or devname_ctx
            result.append({"devname": devname_tag, "ifname": tags.get("ifName",""),
                           "ifalias": tags.get("ifAlias",""),
                           "in_gbps": round(in_bps/1e9,3), "out_gbps": round(out_bps/1e9,3),
                           "pct_in": pct_in, "pct_out": pct_out})
        result.sort(key=lambda x: x["in_gbps"], reverse=True)
        return result[:15]
    except Exception as e:
        print("[Chat influx] Error:", e)
        return []

@app.route("/api/chat", methods=["POST"])
@login_required
def chat_ollama():
    data      = request.get_json() or {}
    pregunta  = data.get("mensaje","").strip()
    historial = data.get("historial",[])
    if not pregunta:
        return jsonify({"ok": False, "error": "mensaje requerido"})
    try:
        intencion = detectar_intencion_python(pregunta)
        print("[Chat] Intencion Python:", intencion)
        if not intencion["necesita_trafico"]:
            intencion_ollama = chat_analizar_intencion(pregunta)
            if intencion_ollama.get("necesita_trafico"):
                intencion["necesita_trafico"] = True
        # Forzar consulta trafico si pregunta menciona porcentajes o utilizacion
        preg_lower = pregunta.lower()
        umbral_match = __import__('re').search(r'(\d+)\s*%', pregunta)
        umbral_pct = int(umbral_match.group(1)) if umbral_match else None
        if any(p in preg_lower for p in ['%','trafico','trafico','saturad','utilizaci','ancho de banda','interfaces sobre','mayor al','supera','capacidad','error','descarte','discard']):
            intencion["necesita_trafico"] = True
            intencion["tipo"] = intencion.get("tipo") or "top_trafico"
            if umbral_pct is not None:
                intencion["umbral_pct"] = umbral_pct
        import sys
        print("[Chat] Intencion:", intencion, flush=True)
        sys.stderr.write("[Chat] Intencion: " + str(intencion) + "\n")
        sys.stderr.flush()
        rt      = load_alertas_rt()
        alarmas = rt.get("alarmas",[])
        activas = [a for a in alarmas if a.get("activa")]
        ts      = rt.get("ts", ahora_str())
        def fmt_a(a):
            return "[" + a.get("tipo","") + "/" + a.get("sev","") + "] " + a.get("router","") + " " + a.get("ifname","") + " | " + a.get("desc","")[:80]
        # Separar alarmas por categoria para que Ollama no las confunda
        equipos_down = [a for a in activas if a.get("tipo")=="equipos_down" or a.get("categoria")=="equipos_core"]
        enlaces_down = [a for a in activas if a.get("tipo") in ("caida_bundle","miembro_down") and a.get("categoria") not in ("equipos_core",)]
        saturaciones = [a for a in activas if a.get("tipo")=="saturacion" or a.get("categoria")=="utilizacion_core"]
        cpu_mem      = [a for a in activas if a.get("tipo")=="recurso" or a.get("categoria")=="cpu_memoria"]
        errores      = [a for a in activas if a.get("tipo") in ("errores","descartes") or a.get("categoria")=="errores_core"]
        drp          = [a for a in activas if a.get("tipo")=="drp" or a.get("categoria")=="drp_core"]
        ctx  = "=== RESUMEN ALARMAS ACTIVAS ===\n"
        ctx += "EQUIPOS CAIDOS (NE DOWN): " + str(len(equipos_down)) + "\n"
        for a in equipos_down: ctx += "  " + fmt_a(a) + "\n"
        ctx += "ENLACES/INTERFACES DOWN: " + str(len(enlaces_down)) + "\n"
        for a in enlaces_down: ctx += "  " + fmt_a(a) + "\n"
        ctx += "SATURACION/UTILIZACION: " + str(len(saturaciones)) + "\n"
        for a in saturaciones: ctx += "  " + fmt_a(a) + "\n"
        ctx += "CPU/MEMORIA: " + str(len(cpu_mem)) + "\n"
        ctx += "ERRORES/DESCARTES: " + str(len(errores)) + "\n"
        ctx += "DRP: " + str(len(drp)) + "\n"
        ctx += "TOTAL ACTIVAS: " + str(len(activas)) + "\n"
        # Forzar necesita_trafico si hay ciudades (independiente de lo que diga Ollama)
        ciudades_check = intencion.get("ciudades", [])
        if ciudades_check:
            intencion["necesita_trafico"] = True
        if intencion.get("necesita_trafico"):
            ciudades = intencion.get("ciudades", [])
            operador = intencion.get("operador")
            # Detectar operador desde el texto si Ollama no lo detecto
            if not operador:
                if "claro" in pregunta.lower():
                    operador = "CLARO"
                elif "vtr" in pregunta.lower():
                    operador = "VTR"
            # Detectar metrica desde el texto si Ollama no la detecto
            metrica = intencion.get("metrica", "trafico")
            if not metrica or metrica == "trafico":
                if "capacidad" in pregunta.lower():
                    intencion["metrica"] = "capacidad"
                elif "error" in pregunta.lower():
                    intencion["metrica"] = "errores"
                elif "discard" in pregunta.lower() or "descarte" in pregunta.lower():
                    intencion["metrica"] = "descartes"
            # Detectar metrica estado desde el texto
            if any(p in pregunta.lower() for p in ["operativ","esta up","esta down","caido","activo","estado de"]):
                intencion["metrica"] = "estado"
            # Detectar descriptor desde el texto
            if "drp" in pregunta.lower():
                intencion["descriptor"] = "bbdrpup"
            else:
                intencion["descriptor"] = intencion.get("descriptor", "bbuplink")
            # Si hay devname especifico, forzar tipo interfaz_especifica
            if intencion.get("devname") and not ciudades:
                intencion["tipo"] = "interfaz_especifica"
            # Forzar tipo ciudades SIEMPRE que haya ciudades
            if ciudades:
                intencion["tipo"] = "ciudades"
            if ciudades:
                if operador == "AMBOS":
                    # Consultar VTR y Claro por separado y combinar
                    devnames_vtr   = buscar_devnames_por_ciudad_operador(ciudades, "VTR")
                    devnames_claro = buscar_devnames_por_ciudad_operador(ciudades, "CLARO")
                    datos_vtr   = chat_query_influx_ciudades(devnames_vtr,   intencion.get("ventana") or "5m", intencion)
                    datos_claro = chat_query_influx_ciudades(devnames_claro, intencion.get("ventana") or "5m", intencion)
                    # Combinar con etiqueta de operador
                    datos_ciudades = {}
                    for k,v in datos_vtr.items():
                        datos_ciudades[k+" (VTR)"] = v
                    for k,v in datos_claro.items():
                        datos_ciudades[k+" (CLARO)"] = v
                else:
                    ciudades_devnames = buscar_devnames_por_ciudad_operador(ciudades, operador)
                    if intencion.get("metrica") == "trafico_y_capacidad":
                        intencion_t = dict(intencion); intencion_t["metrica"] = "trafico"
                        intencion_c = dict(intencion); intencion_c["metrica"] = "capacidad"
                        datos_t = chat_query_influx_ciudades(ciudades_devnames, intencion.get("ventana") or "5m", intencion_t)
                        datos_c = chat_query_influx_ciudades(ciudades_devnames, intencion.get("ventana") or "5m", intencion_c)
                        datos_ciudades = {}
                        for k in datos_t:
                            datos_ciudades[k+" (Trafico)"] = datos_t[k]
                        for k in datos_c:
                            datos_ciudades[k+" (Capacidad)"] = datos_c[k]
                    else:
                        datos_ciudades = chat_query_influx_ciudades(ciudades_devnames, intencion.get("ventana") or "5m", intencion)
                if datos_ciudades:
                    lineas_c = []
                    total_in  = sum(v["total_in_gbps"]  for v in datos_ciudades.values())
                    total_out = sum(v["total_out_gbps"] for v in datos_ciudades.values())
                    op_label  = " (" + (operador if operador != "AMBOS" else "") + ")" if operador and operador != "AMBOS" else ""
                    metrica_ctx = intencion.get("metrica","trafico") if intencion else "trafico"
                    for ciudad, data in datos_ciudades.items():
                        if metrica_ctx == "estado":
                            ups = sum(1 for i in data["interfaces"] if i.get("estado")=="UP")
                            total_if = len(data["interfaces"])
                            lineas_c.append(ciudad + op_label + ": " + str(ups) + "/" + str(total_if) + " interfaces UP")
                            for ifc in data["interfaces"]:
                                lineas_c.append("  " + ifc["devname"] + " " + ifc["ifname"] + " [" + ifc.get("estado","?") + "] " + str(ifc["in_gbps"]) + "Gbps cap")
                        else:
                            lineas_c.append(ciudad + op_label + ": IN=" + str(data["total_in_gbps"]) + "Gbps OUT=" + str(data["total_out_gbps"]) + "Gbps")
                            for ifc in data["interfaces"]:
                                lineas_c.append("  " + ifc["devname"] + " " + ifc["ifname"] + " IN:" + str(ifc["in_gbps"]) + "Gbps(" + str(ifc["pct"]) + "%)")
                        
                    lineas_c.append(">>> TOTAL SUMA " + str(len(datos_ciudades)) + " CIUDADES" + op_label + ": IN=" + str(round(total_in,2)) + "Gbps OUT=" + str(round(total_out,2)) + "Gbps <<<")
                    desc_tipo = "DRP (BBDRPUP)" if intencion.get("descriptor") == "bbdrpup" else "BBUPLINK"
                    nota_drp = " NOTA: Los enlaces DRP con 0 Gbps son NORMALES - solo transportan trafico ante fallas en uplinks principales." if intencion.get("descriptor") == "bbdrpup" else ""
                    ctx += "\n=== TRAFICO " + desc_tipo + op_label + " (TOTAL IN=" + str(round(total_in,2)) + "Gbps OUT=" + str(round(total_out,2)) + "Gbps) ===" + nota_drp + "\n" + "\n".join(lineas_c)
                    resp_c = formatear_respuesta_ciudades(datos_ciudades, intencion.get("metrica","trafico"))
                    return jsonify({"ok":True,"respuesta":resp_c})
                else:
                    desc_label = " DRP" if intencion.get("descriptor") == "bbdrpup" else ""
                    ctx += "\n=== TRAFICO" + desc_label + " POR CIUDAD === Sin datos o enlaces caidos ==="
                datos_if = []
            elif intencion.get("proveedor_isp") and not ciudades:
                proveedor_isp = intencion.get("proveedor_isp")
                metrica_isp = intencion.get("metrica","trafico")
                print("[Chat] ISP:", proveedor_isp, "metrica:", metrica_isp)
                grafana_isp_url = construir_grafana_url(proveedor_isp.replace("_"," "))
                if metrica_isp == "trafico_y_capacidad":
                    res_t, total_t = chat_query_isp_proveedor(proveedor_isp, "trafico", intencion.get("ventana") or "5m", intencion.get("filtro_devname_isp"))
                    res_c, total_c = chat_query_isp_proveedor(proveedor_isp, "capacidad", filtro_devname=intencion.get("filtro_devname_isp"))
                    resp = formatear_respuesta_isp(proveedor_isp, res_t, total_t, res_c, total_c, grafana_isp_url)
                    return jsonify({"ok":True,"respuesta":resp})
                else:
                    res, total = chat_query_isp_proveedor(proveedor_isp, metrica_isp, intencion.get("ventana") or "5m", intencion.get("filtro_devname_isp"))
                    if res:
                        if metrica_isp == "capacidad":
                            resp = formatear_respuesta_isp(proveedor_isp, res_c=res, total_c=total, grafana_url=grafana_isp_url)
                        else:
                            resp = formatear_respuesta_isp(proveedor_isp, res_t=res, total_t=total, grafana_url=grafana_isp_url)
                        return jsonify({"ok":True,"respuesta":resp})
                    else:
                        nombre = PROVEEDOR_NOMBRE_HUMANO.get(proveedor_isp, proveedor_isp)
                        return jsonify({"ok":True,"respuesta":"No hay datos disponibles para " + nombre + " en este momento."})
                datos_if = []
            elif intencion.get("descriptor") == "bbdrpup" and not ciudades and not intencion.get("devname"):
                print("[Chat] Consultando todos los DRP de", operador)
                resultados_drp = chat_query_drp_todos(operador, intencion.get("ventana") or "5m")
                print("[Chat] DRP resultados:", len(resultados_drp), flush=True)
                if resultados_drp:
                    con_trafico = [r for r in resultados_drp if r["con_trafico"]]
                    sin_trafico = [r for r in resultados_drp if not r["con_trafico"]]
                    op_label = " " + operador if operador else ""
                    lineas_drp = []
                    metrica_drp = intencion.get("metrica","trafico") if intencion else "trafico"
                    if metrica_drp == "capacidad":
                        if con_trafico:
                            lineas_drp.append("*** CON TRAFICO REAL: " + str(len(con_trafico)))
                            for r in con_trafico:
                                cap = str(r.get("speed_gbps",0)) + "Gbps"
                                lineas_drp.append("  [ACTIVO] " + r["devname"] + " " + r["ifname"] + " IN:" + str(r["in_gbps"]) + "Gbps cap:" + cap)
                        lineas_drp.append("Capacidad enlaces DRP" + op_label + ":")
                        for r in resultados_drp:
                            cap = str(r.get("speed_gbps",0)) + "Gbps" if r.get("speed_gbps") else "N/A"
                            lineas_drp.append("  " + r["devname"] + " " + r["ifname"] + ": " + cap)
                    else:
                        if con_trafico:
                            lineas_drp.append("*** CON TRAFICO REAL (posible falla uplink): " + str(len(con_trafico)))
                            for r in con_trafico:
                                cap = (" cap:" + str(r.get("speed_gbps",0)) + "Gbps") if r.get("speed_gbps") else ""
                                lineas_drp.append("  [ACTIVO] " + r["devname"] + " " + r["ifname"] + " IN:" + str(r["in_gbps"]) + "Gbps OUT:" + str(r["out_gbps"]) + "Gbps" + cap)
                        else:
                            lineas_drp.append("Todos los enlaces DRP estan en STANDBY (sin fallas activas).")
                        lineas_drp.append("Estado enlaces DRP" + op_label + " (" + str(len(resultados_drp)) + " total):")
                        for r in resultados_drp:
                            estado = "[ACTIVO]" if r["con_trafico"] else "[STANDBY]"
                            cap = (" cap:" + str(r.get("speed_gbps",0)) + "Gbps") if r.get("speed_gbps") else ""
                            lineas_drp.append("  " + estado + " " + r["devname"] + " " + r["ifname"] + " IN:" + str(r["in_gbps"]) + "Gbps" + cap)
                    ctx_drp = "\n=== ENLACES DRP" + op_label + " (" + str(len(resultados_drp)) + " total) ===\n" + "\n".join(lineas_drp)
                    print("[Chat] CTX DRP:", ctx_drp[:200], flush=True)
                    ctx += ctx_drp
                    # Retornar respuesta directa sin Ollama para DRP
                    respuesta_directa = "\n".join(lineas_drp)
                    return jsonify({"ok":True,"respuesta":respuesta_directa})
                else:
                    ctx += "\n=== ENLACES DRP: Sin datos ==="
                datos_if = []
            else:
                devname_usuario = intencion.get("devname")
                if devname_usuario:
                    devnames_reales = chat_get_devnames_influx()
                    devname_real = buscar_devname_real(devname_usuario, devnames_reales)
                    print("[Chat] Mapeo:", devname_usuario, "->", devname_real)
                    intencion["devname"] = devname_real
                # Para capacidad con router especifico usar ciudades con un solo router
                if intencion.get("metrica") == "capacidad" and intencion.get("devname"):
                    devname_real2 = intencion.get("devname")
                    ciudades_1router = {"ROUTER": [devname_real2]}
                    datos_cap = chat_query_influx_ciudades(ciudades_1router, "30m", intencion)
                    if datos_cap and datos_cap.get("ROUTER"):
                        data_r = datos_cap["ROUTER"]
                        lineas_cap = []
                        for ifc in data_r["interfaces"]:
                            lineas_cap.append(ifc["devname"]+" "+ifc["ifname"]+": "+str(ifc["in_gbps"])+"Gbps")
                        total_cap = data_r["total_in_gbps"]
                        ctx += "\n=== CAPACIDAD " + devname_real2 + " (" + str(total_cap) + " Gbps total) ===\n" + "\n".join(lineas_cap)
                    else:
                        ctx += "\n=== CAPACIDAD: Sin datos ==="
                    datos_if = []
                else:
                    datos_if = chat_query_influx(intencion)
            if datos_if:
                umbral = intencion.get("umbral_pct")
                if umbral is not None:
                    # Filtrar por umbral
                    lineas = []
                    sobre_umbral = []
                    for d in datos_if:
                        if d["pct_in"]>umbral or d["pct_out"]>umbral:
                            lineas.append(d["devname"]+" "+d["ifname"]+" IN:"+str(d["in_gbps"])+"Gbps("+str(d["pct_in"])+"%) OUT:"+str(d["out_gbps"])+"Gbps("+str(d["pct_out"])+"%) *** SOBRE "+str(umbral)+"%")
                            sobre_umbral.append(d["devname"]+" "+d["ifname"]+"("+str(d["pct_in"])+"% IN)")
                    if lineas:
                        resumen = " NOTA: "+str(len(sobre_umbral))+" interfaces sobre "+str(umbral)+"%"
                        ctx += "\n=== INTERFACES SOBRE "+str(umbral)+"% ===" + resumen + "\n" + "\n".join(lineas)
                    else:
                        ctx += "\n=== INTERFACES SOBRE "+str(umbral)+"% === NOTA: Ninguna interfaz supera el "+str(umbral)+"%"
                else:
                    # Sin umbral - mostrar solo bundles principales (sin subinterfaces ni fisicas miembro)
                    lineas = []
                    bundles = [d for d in datos_if if not "." in d["ifname"] and
                               any(d["ifname"].startswith(p) for p in ["Bundle-Ether","Eth-Trunk","ae"])]
                    fisicas = [d for d in datos_if if not "." in d["ifname"] and es_fisica(d["ifname"])]
                    # Usar bundles si existen, sino fisicas
                    usar = bundles if bundles else fisicas
                    for d in usar:
                        lineas.append(d["devname"]+" "+d["ifname"]+" IN:"+str(d["in_gbps"])+"Gbps("+str(d["pct_in"])+"%) OUT:"+str(d["out_gbps"])+"Gbps("+str(d["pct_out"])+"%)")
                    total_in = round(sum(d["in_gbps"] for d in usar),2)
                    ctx += "\n=== TRAFICO ROUTER (TOTAL IN="+str(total_in)+"Gbps) ===\n" + "\n".join(lineas)
            else:
                ctx += "\n=== TRAFICO: Sin datos ==="
        system_prompt = ("Eres asistente experto GOC Claro VTR Chile. Responde en espanol, conciso y tecnico.\n"
                        "Hora actual: " + ts + "\n\n" + ctx + "\n\n"
                        "INSTRUCCIONES IMPORTANTES:\n"
                        "1. Si el contexto contiene seccion === ENLACES DRP ===: lista TODOS los enlaces con su estado [ACTIVO] o [STANDBY] y trafico IN.\n"
                        "2. Los enlaces DRP con IN:0.0Gbps son NORMALES y OPERATIVOS - estan en espera. NO digas que no hay datos.\n"
                        "3. Si el contexto contiene datos de trafico o capacidad: presentalos TODOS sin omitir ninguno.\n"
                        "4. NO resumir, NO agrupar, NO omitir routers o interfaces del contexto.\n"
                        "5. Responde SOLO con los datos del contexto anterior.")
        messages = [{"role":"system","content":system_prompt}]
        for msg in historial[-4:]:
            messages.append({"role":msg.get("role","user"),"content":msg.get("content","")})
        messages.append({"role":"user","content":pregunta})
        r = req.post(OLLAMA_URL + "/api/chat",
            json={"model":OLLAMA_MODEL,"stream":False,"messages":messages}, timeout=90)
        respuesta = r.json().get("message",{}).get("content","Sin respuesta")
        return jsonify({"ok":True,"respuesta":respuesta})
    except Exception as e:
        return jsonify({"ok":False,"error":str(e)}), 500

# ---------------------------------------------------------------------------
# CHATBOT MCP � gemma4:12b via vLLM (OpenAI compatible)
# ---------------------------------------------------------------------------
VLLM_URL   = "http://10.68.12.190:1200/v1/chat/completions"
VLLM_MODEL = "gemma4:12b"

MCP_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_alarmas_activas",
            "description": "Retorna las alarmas activas del dashboard GOC. Categorias disponibles: enlaces_core, equipos_core, utilizacion_core, errores_core, cpu_memoria, drp_core. Severidades: critica, importante, advertencia.",
            "parameters": {
                "type": "object",
                "properties": {
                    "categoria": {"type": "string", "description": "Filtrar por categoria: enlaces_core, equipos_core, utilizacion_core, errores_core, cpu_memoria, drp_core (opcional)"},
                    "severidad": {"type": "string", "description": "Filtrar por severidad: critica, importante, advertencia (opcional)"}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_syslog",
            "description": "Retorna eventos de protocolo recientes desde el syslog de los equipos Core MPLS/ISP: BGP, ISIS, OSPF, interfaces, bundles, hardware.",
            "parameters": {
                "type": "object",
                "properties": {
                    "horas": {"type": "integer", "description": "Ventana de tiempo en horas (1, 2, 4, 8, 24). Default 2."}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_trafico_historico",
            "description": "Consulta trafico historico en InfluxDB: maximo, promedio en una ventana de tiempo. Usar para preguntas de pico de trafico, trafico de la semana, maximo historico. Puede filtrar por router, descriptor (BBUPLINK, BBDRPUP, PIT_GOOGLE, etc) y operador.",
            "parameters": {
                "type": "object",
                "properties": {
                    "router":     {"type": "string", "description": "Nombre del router, ej: TEMU-PE1, ANTO-P1 (opcional)"},
                    "descriptor": {"type": "string", "description": "Descriptor ifAlias: BBUPLINK, BBDRPUP, PIT_GOOGLE, PITINTERNACIONAL_LEVEL3, etc (opcional)"},
                    "ventana":    {"type": "string", "description": "Ventana de tiempo: 1h, 24h, 72h, 7d, 30d (default 7d)"},
                    "operador":   {"type": "string", "description": "VTR o CLARO (opcional)"}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_historial",
            "description": "Retorna el historial de alarmas resueltas y activas del dia. Permite filtrar por router.",
            "parameters": {
                "type": "object",
                "properties": {
                    "router": {"type": "string", "description": "Nombre del router a filtrar (opcional)"}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_enlaces_isp",
            "description": "Retorna trafico y capacidad de enlaces ISP/Peering/Contenido en tiempo real desde InfluxDB: Level3, Cirion, Cogent, Google, Facebook, Amazon, Akamai, Cloudflare, Edgeuno, Disney, Fastly, Gcore, Entel, Telefonica, NAP Chile, TATA. Puede filtrar por proveedor y operador (VTR o CLARO).",
            "parameters": {
                "type": "object",
                "properties": {
                    "proveedor": {"type": "string", "description": "Nombre del proveedor, ej: Google, Akamai, Cirion, Level3 (opcional)"},
                    "operador":  {"type": "string", "description": "Operador de red: VTR o CLARO (opcional). VTR usa nodos MX/LCIS, CLARO usa nodos CTL/BBI"}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_enlaces_drp",
            "description": "Retorna trafico y capacidad de los enlaces DRP (Disaster Recovery Plan) de respaldo de la red Core. Consulta InfluxDB en tiempo real usando el descriptor BBDRPUP. Puede filtrar por operador (VTR o CLARO) y ciudad.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ciudad":   {"type": "string", "description": "Filtrar por ciudad o router (opcional)"},
                    "operador": {"type": "string", "description": "Operador: VTR o CLARO (opcional)"}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_inventario",
            "description": "Retorna el inventario real de routers monitoreados por el GOC Core MPLS/ISP. Usar SIEMPRE antes de consultar trafico para obtener los nombres exactos de los equipos.",
            "parameters": {
                "type": "object",
                "properties": {
                    "ciudad": {"type": "string", "description": "Filtrar por ciudad (opcional), ej: Temuco, Antofagasta, Santiago"}
                },
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_trafico",
            "description": "Retorna el trafico actual en Gbps de routers. Puede filtrar por nombre de router, ciudad, operador (VTR o CLARO) o zona (Norte, Sur, Metropolitana). Suma totales cuando hay multiples routers. Incluye capacidad y porcentaje de utilizacion.",
            "parameters": {
                "type": "object",
                "properties": {
                    "router":   {"type": "string", "description": "Nombre o parte del nombre del router (opcional)"},
                    "ciudad":   {"type": "string", "description": "Ciudad o comuna, ej: Temuco, Antofagasta (opcional)"},
                    "operador": {"type": "string", "description": "Operador: VTR o CLARO (opcional)"},
                    "zona":     {"type": "string", "description": "Zona geografica: Norte, Sur, Metropolitana (opcional)"}
                },
                "required": []
            }
        }
    }
]

def mcp_ejecutar_herramienta(nombre, args):
    """Ejecuta una herramienta MCP y retorna el resultado como string."""
    try:
        if nombre == "get_alarmas_activas":
            cat_f = args.get("categoria","").lower()
            sev_f = args.get("severidad","").lower()
            rt = load_alertas_rt()
            alarmas = [a for a in rt.get("alarmas", []) if a.get("activa")]
            if cat_f:
                # Mapeo flexible de categorias
                cat_map = {
                    "drp": "drp_core", "drp_core": "drp_core",
                    "enlaces": "enlaces_core", "enlaces_core": "enlaces_core",
                    "equipos": "equipos_core", "equipos_core": "equipos_core",
                    "errores": "errores_core", "errores_core": "errores_core",
                    "cpu": "cpu_memoria", "memoria": "cpu_memoria", "cpu_memoria": "cpu_memoria",
                    "utilizacion": "utilizacion_core", "utilizacion_core": "utilizacion_core",
                }
                cat_mapped = cat_map.get(cat_f.lower(), cat_f.lower())
                alarmas = [a for a in alarmas if cat_mapped in a.get("categoria","").lower()]
            if sev_f:
                alarmas = [a for a in alarmas if sev_f in a.get("sev","").lower()]
            if not alarmas:
                return "No hay alarmas activas" + (" de categoria " + cat_f if cat_f else "") + " en este momento."
            lines = ["Total alarmas activas: " + str(len(alarmas))]
            for a in alarmas[:50]:
                tipo = a.get("tipo","")
                desc = a.get("desc","")
                if isinstance(desc, dict):
                    desc = desc.get("titulo","") or desc.get("resumen","") or ""
                lines.append("- " + a.get("router","") + " | " + (a.get("ifname","") or "") + " | " + a.get("categoria","") + " | " + a.get("sev","") + " | tipo:" + tipo + " | Desde: " + a.get("detectado",""))
            return "\n".join(lines)

        elif nombre == "get_syslog":
            horas = int(args.get("horas", 2))
            eventos = syslog_get_eventos(horas=horas, max_eventos=50)
            if not eventos:
                return f"Sin eventos de syslog en las ultimas {horas} horas."
            lines = [f"Eventos syslog ultimas {horas}h: {len(eventos)}\n"]
            for ev in eventos[:20]:
                lines.append(f"- {ev.get('equipo','')} | {ev.get('tipo_label','')} | {ev.get('ts','')} | {ev.get('msg','')[:100]}")
            return "\n".join(lines)

        elif nombre == "get_trafico_historico":
            return mcp_get_trafico_historico(args)

        elif nombre == "get_historial":
            router_filtro = args.get("router", "").lower()
            hist = load_json(ALERTAS_HIST_FILE, [])
            if router_filtro:
                hist = [h for h in hist if router_filtro in h.get("router","").lower()]
            if not hist:
                return "Sin eventos en el historial" + (f" para router '{router_filtro}'" if router_filtro else "") + "."
            lines = [f"Historial: {len(hist)} eventos\n"]
            for h in hist[:20]:
                estado = "ACTIVA" if h.get("activa") else "RESUELTA"
                lines.append(f"- [{estado}] {h.get('router','')} | {h.get('ifname','')} | {h.get('categoria','')} | {h.get('detectado','')}")
            return "\n".join(lines)

        elif nombre == "get_inventario":
            ciudad_filtro = args.get("ciudad", "").lower()
            config = load_json(CONFIG_FILE, {})
            routers = config.get("routers_provider", [])
            if ciudad_filtro:
                routers = [r for r in routers if ciudad_filtro in r.get("ciudad","").lower() or ciudad_filtro in r.get("name","").lower()]
            if not routers:
                return f"No se encontraron routers para '{ciudad_filtro}'."
            lines = ["Inventario de routers ("+str(len(routers))+" equipos):"]
            for r in routers:
                lines.append(f"- {r.get('name','')} | {r.get('ciudad','sin ciudad')} | {r.get('grupo','')} | Cap: {r.get('capacidad_gbps','')} Gbps | Interfaz: {r.get('ifname','')}")
            return "\n".join(lines)

        elif nombre == "get_trafico":
            import urllib.request as _ur
            router_f   = args.get("router","").lower()
            ciudad_f   = args.get("ciudad","").lower()
            operador_f = args.get("operador","").upper()
            zona_f     = args.get("zona","").lower()
            # Trafico actual desde alertas_rt
            rt = load_alertas_rt()
            rt_routers = {r.get("devname","").upper(): r for r in rt.get("routers",[])}
            # Consultar Netbox con paginacion
            nb_devs = []
            try:
                offset = 0
                while True:
                    nb_url = NETBOX_URL + "/api/dcim/devices/?tenant_id=1&limit=500&offset=" + str(offset)
                    nb_req = _ur.Request(nb_url, headers={"Authorization": "Token " + NETBOX_TOKEN})
                    nb_data = json.loads(_ur.urlopen(nb_req, timeout=15).read())
                    nb_devs += nb_data.get("results", [])
                    if not nb_data.get("next"):
                        break
                    offset += 500
            except:
                nb_devs = []
            filtrados = []
            for dev in nb_devs:
                cf = dev.get("custom_fields", {})
                nombre_dev = dev.get("name","")
                op  = (cf.get("operador") or "").upper()
                zo  = (cf.get("zona") or "").lower()
                com = (cf.get("comuna") or "").lower()
                if router_f and router_f not in nombre_dev.lower():
                    continue
                if operador_f and op != operador_f:
                    continue
                if zona_f and zona_f not in zo:
                    continue
                if ciudad_f and ciudad_f not in com:
                    continue
                # Buscar trafico en rt - matching flexible
                rt_data = None
                # Extraer nombre base sin dominio ni sufijos
                nombre_base = nombre_dev.upper().split(".")[0].replace("-","_").replace(" ","_")
                for key in rt_routers:
                    key_base = key.upper().replace("-","_").replace(" ","_")
                    # Match exacto o parcial del nombre base
                    if key_base == nombre_base:
                        rt_data = rt_routers[key]
                        break
                    # Match parcial: TEMU_PE1 en TEMU_PE1_ASR9010
                    if key_base in nombre_base or nombre_base in key_base:
                        rt_data = rt_routers[key]
                        break
                filtrados.append({
                    "nombre": nombre_dev,
                    "ciudad": cf.get("comuna",""),
                    "operador": op,
                    "zona": cf.get("zona",""),
                    "in_gbps":  rt_data.get("in_gbps",0) if rt_data else None,
                    "out_gbps": rt_data.get("out_gbps",0) if rt_data else None,
                    "cap_gbps": rt_data.get("cap_gbps",0) if rt_data else None,
                    "alerta":   rt_data.get("alerta",False) if rt_data else False,
                })
            if not filtrados:
                return "No se encontraron routers con los filtros indicados."
            # Calcular totales solo de los que tienen trafico
            con_trafico = [r for r in filtrados if r["in_gbps"] is not None]
            total_in  = round(sum(r["in_gbps"] for r in con_trafico), 2)
            total_out = round(sum(r["out_gbps"] for r in con_trafico), 2)
            total_cap = round(sum(r["cap_gbps"] for r in con_trafico), 2)
            lines = ["Trafico (" + str(len(filtrados)) + " equipos, " + str(len(con_trafico)) + " con datos):"]
            lines.append("Total IN:  " + str(total_in) + " Gbps")
            lines.append("Total OUT: " + str(total_out) + " Gbps")
            lines.append("Capacidad: " + str(total_cap) + " Gbps")
            if total_cap > 0:
                lines.append("Utilizacion: " + str(round(total_in/total_cap*100,1)) + "%")
            lines.append("")
            lines.append("Detalle:")
            for r in filtrados[:30]:
                if r["in_gbps"] is not None:
                    cap = r["cap_gbps"]
                    pct = str(round(r["in_gbps"]/cap*100)) + "%" if cap > 0 else "N/A"
                    alerta = " [ALERTA]" if r["alerta"] else ""
                    lines.append("- " + r["nombre"] + " | " + r["ciudad"] + " | " + r["operador"] + " | IN:" + str(r["in_gbps"]) + " OUT:" + str(r["out_gbps"]) + " Cap:" + str(cap) + " Gbps " + pct + alerta)
                else:
                    lines.append("- " + r["nombre"] + " | " + r["ciudad"] + " | " + r["operador"] + " | sin datos de trafico")
            return "\n".join(lines)

        elif nombre == "get_enlaces_isp":
            proveedor  = args.get("proveedor","").lower()
            operador_f = args.get("operador","").upper()
            # Mapa proveedor -> descriptor InfluxDB
            prov_map = {
                "level3": "PITINTERNACIONAL_LEVEL3", "cirion": "PITINTERNACIONAL_LEVEL3",
                "cogent": "PITINTERNACIONAL_COGENT",
                "google": "PIT_GOOGLE", "facebook": "PIT_FACEBOOK",
                "amazon": "PIT_AMAZON", "akamai": "PIT_AKAMAI",
                "microsoft": "PIT_MICROSOFT", "cloudflare": "PIT_CLOUDFLARE",
                "edgeuno": "PIT_EDGEUNO", "disney": "PIT_DISNEY",
                "fastly": "PIT_FASTLY", "gcore": "PIT_GCORE",
                "entel": "PIT_ENTEL", "telefonica": "PIT_MOVISTAR",
                "napchile": "PIT_NAP", "chile nap": "PIT_NAP",
                "tata": "TATA",
            }
            # Cargar mapa ISP (operador por enlace)
            isp_map = load_json(os.path.join(DATA_DIR, "isp_map.json"), {})
            # Construir set de ifnames por operador
            vtr_ifnames  = set()
            claro_ifnames = set()
            for k, v in isp_map.items():
                if v.get("operador") == "VTR":
                    vtr_ifnames.add(v.get("ifname","").split(".")[0])
                elif v.get("operador") == "CLARO":
                    claro_ifnames.add(v.get("ifname","").split(".")[0])
            # Determinar descriptor
            if proveedor:
                descriptor = prov_map.get(proveedor)
                if not descriptor:
                    for k,v in prov_map.items():
                        if proveedor in k:
                            descriptor = v
                            break
                if not descriptor:
                    return "Proveedor '" + proveedor + "' no reconocido. Disponibles: " + ", ".join(prov_map.keys())
                res_t, total_t = chat_query_isp_proveedor(descriptor, "trafico", "5m")
                res_c, total_c = chat_query_isp_proveedor(descriptor, "capacidad")
                # Mapa capacidad
                cap_map = {}
                if isinstance(res_c, list):
                    for rc in res_c:
                        key = rc.get("devname","") + "|" + rc.get("ifname","")
                        cap_map[key] = rc.get("cap_gbps", 0)
                # Filtrar por operador usando isp_map
                enlaces = []
                if isinstance(res_t, list):
                    for r in res_t:
                        devname = r.get("devname","")
                        ifname  = r.get("ifname","").split(".")[0]
                        if operador_f:
                            # Buscar en isp_map por ifname
                            op_enlace = None
                            for k,v in isp_map.items():
                                if v.get("ifname","").split(".")[0] == ifname and devname.replace("_","-").replace("CENTURYLINK-QFX-PEERING","CTL-QFX") in k.replace("_","-").upper() or devname.upper().replace("_","-") in k.upper():
                                    op_enlace = v.get("operador","")
                                    break
                            # Fallback por devname patterns
                            if not op_enlace:
                                dn = devname.upper()
                                if any(x in dn for x in ["MX960","LCIS","CTL-QFX","CENTURYLINK_QFX"]):
                                    op_enlace = "VTR"
                                elif any(x in dn for x in ["BBI","FNR","SLT","PIT"]):
                                    op_enlace = "CLARO"
                            if op_enlace != operador_f:
                                continue
                        key = devname + "|" + r.get("ifname","")
                        r["cap_gbps"] = cap_map.get(key, 0)
                        enlaces.append(r)
                total_in_f  = round(sum(r.get("in_gbps",0) for r in enlaces), 2)
                total_cap_f = round(sum(r.get("cap_gbps",0) for r in enlaces), 2)
                titulo = proveedor.title() + (" (" + operador_f + ")" if operador_f else "")
                lines = ["Trafico " + titulo + ":"]
                lines.append("Total IN: " + str(total_in_f) + " Gbps")
                lines.append("Capacidad: " + str(total_cap_f) + " Gbps")
                if total_cap_f > 0:
                    lines.append("Utilizacion: " + str(round(total_in_f/total_cap_f*100,1)) + "%")
                lines.append("")
                for r in enlaces[:15]:
                    cap_r = r.get("cap_gbps",0)
                    pct = str(round(r.get("in_gbps",0)/cap_r*100,1))+"%" if cap_r>0 else "N/D"
                    lines.append("- " + r.get("devname","") + " | " + r.get("ifname","") + " | IN:" + str(round(r.get("in_gbps",0),2)) + " OUT:" + str(round(r.get("out_gbps",0),2)) + " Cap:" + str(cap_r) + " Gbps | " + pct)
                return "\n".join(lines)
            else:
                # Todos los proveedores
                lines = ["Trafico ISP/Peering/Contenido" + (" (" + operador_f + ")" if operador_f else "") + ":"]
                for prov, desc in prov_map.items():
                    try:
                        res_t, total_t = chat_query_isp_proveedor(desc, "trafico", "5m")
                        res_c, total_c = chat_query_isp_proveedor(desc, "capacidad")
                        if total_t > 0:
                            pct = str(round(total_t/total_c*100,1))+"%" if total_c>0 else "N/A"
                            lines.append("- " + prov.title() + ": IN " + str(round(total_t,2)) + " Gbps | Cap " + str(round(total_c,2)) + " Gbps | " + pct)
                    except:
                        pass
                return "\n".join(lines)


        elif nombre == "get_enlaces_drp":
            ciudad_f  = args.get("ciudad","").lower()
            operador_f = args.get("operador","").upper()
            # Consultar InfluxDB por descriptor BBDRPUP - solo bundles sin subinterface
            q_t = ('SELECT non_negative_derivative(mean("ifHCInOctets"),1s)*8 AS in_bps,'
                   ' non_negative_derivative(mean("ifHCOutOctets"),1s)*8 AS out_bps'
                   ' FROM "trafico"'
                   ' WHERE "ifAlias" =~ /BBDRPUP/ AND time > now()-10m'
                   ' GROUP BY time(300s),"devname","ifName","ifAlias" fill(null)')
            q_c = ('SELECT last("ifSpeed") AS speed, last("ifOper") AS oper'
                   ' FROM "trafico"'
                   ' WHERE "ifAlias" =~ /BBDRPUP/ AND time > now()-30m'
                   ' GROUP BY "devname","ifName","ifAlias"')
            try:
                data_t = influx_query(q_t, timeout=25)
                data_c = influx_query(q_c, timeout=25)
            except Exception as e:
                return "Error consultando InfluxDB: " + str(e)
            series_t = data_t.get("results",[{}])[0].get("series",[])
            series_c = data_c.get("results",[{}])[0].get("series",[])
            # Mapa capacidad y estado operacional
            cap_map = {}
            oper_map = {}
            for s in series_c:
                tags = s.get("tags",{})
                ifname = tags.get("ifName","")
                if "." in ifname:
                    continue
                key = tags.get("devname","") + "|" + ifname
                vals = [v for v in s.get("values",[]) if v[1] is not None]
                if vals:
                    cap_map[key] = round(vals[-1][1]/1000, 1)  # Mbps -> Gbps
                    oper_map[key] = int(vals[-1][2]) if vals[-1][2] is not None else 1
            # Procesar trafico - solo bundles
            bundle_prefixes = ["Bundle-Ether","Eth-Trunk","ae","port-channel","Bundle-ether"]
            enlaces = []
            for s in series_t:
                tags   = s.get("tags",{})
                ifname = tags.get("ifName","")
                devname = tags.get("devname","")
                alias  = tags.get("ifAlias","")
                # Solo bundles sin subinterface
                if "." in ifname:
                    continue
                if not any(ifname.startswith(p) for p in bundle_prefixes):
                    continue
                # Filtrar por ciudad
                if ciudad_f and ciudad_f not in devname.lower() and ciudad_f not in alias.lower():
                    continue
                # Filtrar por operador
                # VTR: devnames con .vtr.cl o MX480 (OSOR,LANG son VTR)
                es_vtr = (".vtr.cl" in devname.lower() or
                          "OSOR_PE" in devname.upper() or
                          "LANG_PE" in devname.upper())
                es_claro = not es_vtr
                if operador_f == "VTR" and not es_vtr:
                    continue
                if operador_f == "CLARO" and not es_claro:
                    continue
                vals = [v for v in s.get("values",[]) if v[1] is not None and v[2] is not None]
                if not vals:
                    continue
                v = vals[-1]
                in_gbps  = round(v[1]/1e9, 2)
                out_gbps = round(v[2]/1e9, 2)
                cap_gbps = cap_map.get(devname+"|"+ifname, 0)
                enlaces.append({
                    "devname": devname, "ifname": ifname,
                    "alias": alias[:60],
                    "in_gbps": in_gbps, "out_gbps": out_gbps, "cap_gbps": cap_gbps, "oper": oper_map.get(devname+"|"+ifname, 1)
                })
            if not enlaces:
                return "No se encontraron enlaces DRP con los filtros indicados."
            total_in  = round(sum(e["in_gbps"] for e in enlaces), 2)
            total_out = round(sum(e["out_gbps"] for e in enlaces), 2)
            total_cap = round(sum(e["cap_gbps"] for e in enlaces), 2)
            titulo = "Enlaces DRP" + (" " + operador_f if operador_f else "") + (" - " + ciudad_f.title() if ciudad_f else "")
            lines = [titulo + " (" + str(len(enlaces)) + " bundles):"]
            lines.append("Total IN: " + str(total_in) + " Gbps | OUT: " + str(total_out) + " Gbps | Cap: " + str(total_cap) + " Gbps")
            lines.append("")
            for e in sorted(enlaces, key=lambda x: (x["oper"], -x["in_gbps"])):
                cap = e["cap_gbps"]
                pct = str(round(e["in_gbps"]/cap*100,1))+"%" if cap>0 else "N/D"
                estado = "DOWN" if e.get("oper",1)==2 else ("ACTIVO" if e["in_gbps"]>0 else "STANDBY")
                lines.append("- " + e["devname"] + " | " + e["ifname"] + " | " + estado + " | IN:" + str(e["in_gbps"]) + " OUT:" + str(e["out_gbps"]) + " Cap:" + str(cap) + "G | " + pct)
            return "\n".join(lines)

        return f"Herramienta '{nombre}' no reconocida."
    except Exception as e:
        return f"Error ejecutando {nombre}: {str(e)}"

@app.route("/api/chat/mcp", methods=["POST"])
@login_required
def chat_mcp():
    data     = request.get_json() or {}
    pregunta = data.get("mensaje", "").strip()
    historial = data.get("historial", [])
    if not pregunta:
        return jsonify({"ok": False, "error": "mensaje requerido"})

    usuario = session.get("user", "ingeniero")
    SYSTEM = ("Eres un asistente experto en redes Core MPLS/ISP de Claro VTR Chile. "
              "Ayudas a los ingenieros del GOC (Network Operations Center) a monitorear la red. "
              "El ingeniero con quien hablas se llama " + usuario + ". "
              "REGLA IMPORTANTE: SIEMPRE usa las herramientas disponibles para responder preguntas "
              "sobre el estado de la red. NUNCA respondas desde tu conocimiento general cuando "
              "se trate de estado actual, trafico, alarmas o enlaces. "
              "Herramientas disponibles: "
              "get_alarmas_activas (alarmas del dashboard, filtra por categoria: drp_core, enlaces_core, errores_core, cpu_memoria, utilizacion_core), "
              "get_enlaces_drp (trafico y estado de enlaces DRP, filtra por operador VTR/CLARO y ciudad), "
              "get_enlaces_isp (trafico enlaces ISP/peering: Google, Akamai, Level3, Cogent, etc.), "
              "get_trafico (trafico routers por ciudad/operador/zona), "
              "get_syslog (eventos de protocolo: BGP, ISIS, interfaces), "
              "get_historial (historial de alarmas), "
              "get_inventario (inventario de routers). "
              "Responde siempre en espanol, claro y conciso. "
              "Para preguntas de enlaces caidos: usa get_alarmas_activas con la categoria correspondiente. "
              "Ejemplos de uso de herramientas: "
              "- enlaces DRP caidos -> get_alarmas_activas(categoria=drp_core) "
              "- interfaces down -> get_alarmas_activas(categoria=enlaces_core) "
              "- equipos caidos -> get_alarmas_activas(categoria=equipos_core) "
              "- errores en interfaces -> get_alarmas_activas(categoria=errores_core) "
              "- CPU/memoria alta -> get_alarmas_activas(categoria=cpu_memoria) "
              "- trafico de un router -> get_trafico(router=nombre) ""- trafico historico/punta/semana -> get_trafico_historico(router=nombre, ventana=7d) "
              "- trafico de una ciudad -> get_trafico(ciudad=nombre) "
              "- trafico Google/Akamai/etc -> get_enlaces_isp(proveedor=nombre) "
              "- estado enlaces DRP -> get_enlaces_drp() "
              "- eventos BGP/ISIS/OSPF -> get_syslog(horas=2) "
              "NUNCA respondas sin consultar las herramientas primero.")

    messages = [{"role": "system", "content": SYSTEM}]
    for msg in historial[-6:]:
        msg_content = msg.get("content","")
        # Filtrar mensajes con raw tool_calls de gemma
        if msg_content and ("<|tool_call>" in msg_content or "call:get_" in msg_content):
            continue
        messages.append({"role": msg.get("role","user"), "content": msg_content})
    messages.append({"role": "user", "content": pregunta})

    try:
        # Primera llamada al modelo - forzar uso de herramientas
        # Determinar si la pregunta requiere datos en tiempo real
        keywords_rt = ["alarm","caido","down","trafico","drp","enlace","isp","google","akamai","historico","punta","semana","maximo","promedio","semana","72h","24h",
                       "bgp","isis","syslog","router","interfaz","capacidad","estado","activ",
                       "cpu","memoria","error","descarte","saturacion","utilizacion"]
        necesita_herramienta = any(k in pregunta.lower() for k in keywords_rt)
        tool_choice = "required" if necesita_herramienta else "auto"
        r = req.post(VLLM_URL,
            json={"model": VLLM_MODEL, "messages": messages, "tools": MCP_TOOLS,
                  "tool_choice": tool_choice, "max_tokens": 1000},
            timeout=60)
        resp = r.json()
        choice = resp.get("choices", [{}])[0]
        msg_resp = choice.get("message", {})

        # Si el modelo quiere usar herramientas
        tool_calls = msg_resp.get("tool_calls", [])
        if tool_calls:
            messages.append({"role": "assistant", "content": None, "tool_calls": tool_calls})
            # Ejecutar cada herramienta
            ultimo_resultado = ""
            for tc in tool_calls:
                fn_name = tc.get("function", {}).get("name", "")
                fn_args = {}
                try:
                    import json as _j
                    fn_args = _j.loads(tc.get("function", {}).get("arguments", "{}"))
                except:
                    pass
                resultado = mcp_ejecutar_herramienta(fn_name, fn_args)
                ultimo_resultado = resultado
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", ""),
                    "content": resultado
                })
            # Segunda llamada con resultados de herramientas
            r2 = req.post(VLLM_URL,
                json={"model": VLLM_MODEL, "messages": messages, "max_tokens": 1000},
                timeout=60)
            r2_data = r2.json()
            respuesta = r2_data.get("choices",[{}])[0].get("message",{}).get("content","")
            # Si el modelo falla, retornar resultado directo de la herramienta
            if not respuesta or "<|tool_call>" in respuesta or "call:get_" in respuesta:
                respuesta = ultimo_resultado
        else:
            raw = msg_resp.get("content", "") or ""
            # Detectar tool_call en formato texto (gemma a veces lo hace asi)
            if "<|tool_call>" in raw or "call:" in raw:
                import re as _re, json as _j
                # Intentar extraer nombre y args
                # Limpiar formato especial de gemma
                raw_clean = raw.replace('<|"|>', '"').replace('<|tool_call>', '').strip()
                m = _re.search(r'call:([a-zA-Z_]+)\{(.+)\}', raw_clean, _re.DOTALL)
                if m:
                    fn_name = m.group(1)
                    try:
                        args_str = m.group(2).strip()
                        # Convertir formato key:value a JSON
                        args_str = _re.sub(r'([a-zA-Z_]+):', lambda m: '"' + m.group(1) + '":', args_str)
                        fn_args = _j.loads("{" + args_str + "}")
                    except:
                        # Fallback: extraer key-value manualmente
                        fn_args = {}
                        for pair in _re.findall(r'"([^"]+)":\s*"([^"]+)"', args_str):
                            fn_args[pair[0]] = pair[1]
                    resultado = mcp_ejecutar_herramienta(fn_name, fn_args)
                    # Segunda llamada con resultado
                    messages.append({"role": "assistant", "content": raw})
                    messages.append({"role": "user", "content": "Resultado de la herramienta " + fn_name + ": " + resultado + ". Ahora responde al ingeniero en espanol basandote en estos datos."})
                    r2 = req.post(VLLM_URL,
                        json={"model": VLLM_MODEL, "messages": messages, "max_tokens": 1000},
                        timeout=60)
                    respuesta = r2.json().get("choices",[{}])[0].get("message",{}).get("content","Sin respuesta")
                else:
                    respuesta = raw
            else:
                respuesta = raw or "Sin respuesta"

        return jsonify({"ok": True, "respuesta": respuesta})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ---------------------------------------------------------------------------
# MCP TOOL: get_trafico_historico
# ---------------------------------------------------------------------------
@app.route("/api/mcp/trafico_historico", methods=["POST"])
@login_required  
def mcp_trafico_historico():
    pass  # placeholder

def mcp_get_trafico_historico(args):
    """Consulta trafico historico en InfluxDB por devname+ifname o descriptor."""
    import urllib.request as _ur
    router_f   = args.get("router","").strip()
    descriptor = args.get("descriptor","").strip()  # BBUPLINK, BBDRPUP, PIT_GOOGLE, etc
    ventana    = args.get("ventana","7d")  # 1h, 24h, 7d
    operador_f = args.get("operador","").upper()

    # Mapear ventana a GROUP BY interval
    interval_map = {"1h":"5m", "24h":"30m", "7d":"1h", "30d":"6h", "72h":"1h"}
    interval = interval_map.get(ventana, "1h")

    results = []

    if router_f:
        # Buscar por router - primero encontrar ifName con BBUPLINK
        # Consultar config para encontrar la interfaz principal
        config_data = load_json(CONFIG_FILE, {})
        ifname = None
        for r in config_data.get("routers_provider",[]):
            if router_f.lower() in r.get("name","").lower():
                ifname = r.get("ifname","")
                break

        # Si no encontramos en config, buscar en InfluxDB por BBUPLINK
        if not ifname:
            q_if = ('SELECT last(\"ifHCInOctets\") FROM \"trafico\"'
                   ' WHERE \"devname\" =~ /' + router_f.replace("-","_").replace(".","[.]") + '/'
                   ' AND \"ifAlias\" =~ /BBUPLINK.*BUNDLE/'
                   ' AND time > now()-1h'
                   ' GROUP BY \"devname\",\"ifName\"')
            try:
                d = influx_query(q_if, timeout=15)
                series = d.get("results",[{}])[0].get("series",[])
                if series:
                    ifname = series[0].get("tags",{}).get("ifName","")
                    devname_real = series[0].get("tags",{}).get("devname","")
            except:
                pass

        if not ifname:
            return "No se encontro interfaz principal para router '" + router_f + "'. Verifica el nombre exacto."

        # Buscar devname real en InfluxDB
        devnames_reales = buscar_devname_influx_real(router_f)
        if not devnames_reales:
            return "No se encontro el router '" + router_f + "' en InfluxDB."
        devname_real = devnames_reales[0]
        q = ('SELECT non_negative_derivative(mean(\"ifHCInOctets\"),1s)*8 AS in_bps,'
             ' non_negative_derivative(mean(\"ifHCOutOctets\"),1s)*8 AS out_bps'
             ' FROM \"trafico\"'
             " WHERE \"devname\" = '" + devname_real + "'"
             ' AND \"ifName\" = \'' + ifname + '\''
             ' AND time > now()-' + ventana +
             ' GROUP BY time(' + interval + '),\"devname\",\"ifName\"')
        try:
            data = influx_query(q, timeout=30)
            series_list = data.get("results",[{}])[0].get("series",[])
            for s in series_list:
                tags = s.get("tags",{})
                vals = [v for v in s.get("values",[]) if v[1] is not None]
                if not vals:
                    continue
                max_in  = max(v[1] for v in vals)
                max_out = max(v[2] for v in vals if v[2] is not None) if any(v[2] for v in vals) else 0
                avg_in  = sum(v[1] for v in vals)/len(vals)
                results.append({
                    "devname": tags.get("devname",""),
                    "ifname":  tags.get("ifName",""),
                    "max_in_gbps":  round(max_in/1e9,2),
                    "max_out_gbps": round(max_out/1e9,2),
                    "avg_in_gbps":  round(avg_in/1e9,2),
                    "puntos": len(vals)
                })
        except Exception as e:
            return "Error consultando InfluxDB: " + str(e)

    elif descriptor:
        # Consultar por descriptor (BBUPLINK, BBDRPUP, PIT_GOOGLE, etc)
        alias_regex = descriptor.replace("_","[_]?")
        q = ('SELECT non_negative_derivative(mean("ifHCInOctets"),1s)*8 AS in_bps,'
             ' non_negative_derivative(mean("ifHCOutOctets"),1s)*8 AS out_bps'
             ' max(non_negative_derivative(mean(\"ifHCOutOctets\"),1s)*8) AS max_out'
             ' FROM \"trafico\"'
             ' WHERE \"ifAlias\" =~ /' + alias_regex + '/'
             ' AND time > now()-' + ventana +
             ' GROUP BY \"devname\",\"ifName\"')
        try:
            data = influx_query(q, timeout=30)
            series_list = data.get("results",[{}])[0].get("series",[])
            for s in series_list:
                tags = s.get("tags",{})
                ifname = tags.get("ifName","")
                if "." in ifname:
                    continue
                vals = [v for v in s.get("values",[]) if v[1] is not None]
                if not vals:
                    continue
                devname = tags.get("devname","")
                if operador_f == "VTR" and ".vtr.cl" not in devname.lower():
                    continue
                if operador_f == "CLARO" and ".vtr.cl" in devname.lower():
                    continue
                max_in  = max(v[1] for v in vals)
                max_out = max(v[2] for v in vals if v[2] is not None) if any(v[2] for v in vals) else 0
                results.append({
                    "devname": devname,
                    "ifname":  ifname,
                    "max_in_gbps":  round(max_in/1e9,2),
                    "max_out_gbps": round(max_out/1e9,2),
                    "puntos": len(vals)
                })
        except Exception as e:
            return "Error consultando InfluxDB: " + str(e)
    else:
        return "Se requiere 'router' o 'descriptor' como parametro."

    if not results:
        return "Sin datos historicos para los filtros indicados en ventana " + ventana + "."

    total_max_in = round(sum(r["max_in_gbps"] for r in results),2)
    lines = ["Trafico historico (" + ventana + ") - " + str(len(results)) + " enlaces:"]
    lines.append("Pico maximo total IN: " + str(total_max_in) + " Gbps")
    lines.append("")
    for r in sorted(results, key=lambda x: x["max_in_gbps"], reverse=True)[:20]:
        avg = " | Avg IN: " + str(r.get("avg_in_gbps",0)) + " Gbps" if r.get("avg_in_gbps") else ""
        lines.append("- " + r["devname"] + " | " + r["ifname"] + " | Max IN: " + str(r["max_in_gbps"]) + " | Max OUT: " + str(r["max_out_gbps"]) + avg)
    return "\\n".join(lines)
