 tshark -r chall.pcap -Y "icmp.type == 8" -T fields -e data.data | tr -d '\n ' | xxd -r -p | tr -dc 'A-Za-z0-9+/=' | base64 -d
Welcome to Lag'n'Crash 6.0, we hope that you will enjoy this event that we've prepared for you, as well as the finals challenge if you do end up qualifying for it.

We've spent a lot of time preparing this event, from sponsors and logistics, to challenge creation and infra. Whether you're here to win prizes, learn something new or even to make new friends, we hope that you will enjoy this event, and come back again for future iterations of LNC

Anyways, here's the flag you've been looking for: LNC26{9f1dac270d99477b98e0c58bc4db0cfe}
