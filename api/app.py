from fastapi import FastAPI, Request, Response
from pydantic import BaseModel
import json
import redis
import ipaddress
import logging
from datetime import datetime

class smartlog():
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def info(self,msg):
        self.logger.info(f'{Request.url} - {msg}')
        print(f'{Request.url} - {msg}')
    
    def debug(self,msg):
        self.logger.debug(f'{Request.url} - {msg}')
        print(f'{Request.url} - {msg}')

    def warn(self,msg):
        self.logger.warn(f'{Request.url} - {msg}')
        print(f'{Request.url} - {msg}')

    def error(self,msg):
        self.logger.error(f'{Request.url} - {msg}')
        print(f'{Request.url} - {msg}')

log = smartlog()

app = FastAPI()

r = redis.Redis('ha-redis')

## Fonctions de contôle :
def is_an_otp_connection(authtype):
	#cleartrust authtype = 8 or 9 => rsa otp connection
	if authtype in ('8','9'):
		return True
	return False

def uid_is_blacklisted(uid):
    if r.exists(f'uidblacklist-{uid}'):
        return True
    else:
        return False


def ip_is_secure(ip):
    #ipaddress as object IPV4
    try:
        ipaddr = ipaddress.ip_address(ip)
    except:
        log.error(f"impossible d'evaluer l'ip : {ip}")
        return False

    #first check blacklist
    if r.exists(f'ipblacklist-{ip}'):
        return False
                
    #next check whitelists (whitelist + ip france)
    if r.exists(f'ipwhitelist-{ip}'):
        return True

    return False

def uid_ip_allowed(uid,ip):
    if r.exists(f'scmn-{uid}-{ip}'):
        return True
    else:
        return False

# smartResponse : renvoie le code 401 si msg commence par False
def smartResponse(msg):
	if msg[:5] == 'False':
		code=401
	else:
		code=200
	log.info(msg)
	return Response(msg, status_code=code)

## Main
class ContextSmartCheck(BaseModel):
    uid: str
    ip: str
    useragent: str
    authtype: str

@app.post("/smartcheckmfaneeded")
async def smartcheckmfaneeded(context: ContextSmartCheck):
    #cas ip : s'il y en a plusieurs, on prend la premiere
    firstIp = context.ip.split(',')[0]

    infojson={'uid':context.uid,'ip':firstIp,'useragent':context.useragent,'authtype':context.authtype}
    
    info=json.dumps(infojson)

    # Si connexion Otp => pas de MFA
    if is_an_otp_connection(context.authtype):
        return smartResponse(f'False - noMfaNeeded - Otp connection - {info}')
    
    # Sinon Uid in BlackList => MFA
    elif uid_is_blacklisted(context.uid):
        return smartResponse(f'True - mfaNeeded - uid {context.uid} mfaforced - {info}')
    
    # Sinon si Ip est secure
    elif ip_is_secure(context.ip):
        return smartResponse(f'False - noMfaNeeded - ip is secure - {info}')

    # Sinon si le couple uid-ip existe
    elif uid_ip_allowed(context.uid,context.ip):
        return smartResponse(f'False - noMfaNeeded - uid-ip allowed - {info}')
    
    # Sinon MFA
    else:
        return smartResponse(f'True - mfaNeeded - MFA par defaut - {info}')




class ContextMFALoginSuccess(BaseModel):
    uid: str
    ip: str

@app.post('/postloginsuccess')
async def postloginsuccess(context: ContextMFALoginSuccess):
    """PostLoginSuccess : Action Après Login MFA complet
        enregistrement dans redis de la clé scmn-{uid}-{ip} = "datedujour"
    """
    #cas ip : s'il y en a plusieurs, on prend la premiere
    firstIp = context.ip.split(',')[0]

    #test ipaddress as object IPV4
    try:
        ipaddr = ipaddress.ip_address(context.ip)
    except:
        return smartResponse(f'postloginsuccess : impossible d\'evaluer l\'ip {context.ip}')
    
    keyname=f'scmn-{context.uid}-{firstIp}'
    keyvalue=datetime.today().strftime('%Y-%m-%d') #date au format 06/07/2023
    keyex=7776000 #expiration = 3 mois = 90 jours = 7776000s

    #enregistrement de la clé dans Rédis
    res=r.set(keyname,keyvalue,keyex)

    if res:
        # sauvegarde clé API OK
        msg=f'Enregistrement dans redis de la clé {keyname}'
    else:
        msg=f'Erreur d\'enregistrement dans redis de la clé {keyname}'
    log.info(msg)
    return smartResponse(f'postloginsuccess : {msg}')