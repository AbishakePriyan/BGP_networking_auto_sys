"""On-demand current RIPEstat RPKI evidence; not a maliciousness decision."""
from datetime import datetime, timezone
import ipaddress
import httpx

ENDPOINT='https://stat.ripe.net/data/rpki-validation/data.json'
STATES={'valid','invalid_asn','invalid_length','unknown'}

def interpret_response(payload,prefix,asn):
    network=ipaddress.ip_network(prefix,strict=True)
    if type(asn) is not int or not 1 <= asn <= 4294967295: raise ValueError('Invalid origin ASN')
    if not isinstance(payload,dict) or payload.get('status')!='ok' or not isinstance(payload.get('data'),dict):
        raise ValueError('RPKI provider returned an invalid response')
    data=payload['data']
    try:
        if ipaddress.ip_network(data.get('prefix'),strict=True)!=network or int(data.get('resource'))!=asn:
            raise ValueError('Provider response does not match request')
    except (TypeError,ValueError) as exc: raise ValueError('Provider response does not match request') from exc
    if data.get('status') not in STATES: raise ValueError('Unrecognized RPKI status')
    return {'source':'RIPEstat RPKI validation','source_url':ENDPOINT,'prefix':str(network),'origin_asn':asn,
            'status':data['status'],'validator':data.get('validator'),'provider_time':payload.get('time'),
            'retrieved_at_utc':datetime.now(timezone.utc).isoformat(), 'cached_by_provider':payload.get('cached'),
            'note':'Current RPKI validation is not proof of malicious intent or historical validity; it does not verify route recovery.'}

async def validate_rpki(prefix,asn):
    ipaddress.ip_network(prefix,strict=True)
    if type(asn) is not int or not 1 <= asn <= 4294967295: raise ValueError('Invalid origin ASN')
    async with httpx.AsyncClient(timeout=12, follow_redirects=False) as client:
        response=await client.get(ENDPOINT,params={'resource':str(asn),'prefix':prefix,'sourceapp':'bgpguard-v2'})
        response.raise_for_status()
        return interpret_response(response.json(),prefix,asn)
