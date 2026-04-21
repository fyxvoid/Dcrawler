from search import get_tor_session
try:
    session = get_tor_session()
    r = session.get('http://httpbin.org/ip', timeout=10)
    print("Clearweb via Tor:", r.json())
    r_onion = session.get('http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/', timeout=20)
    print("Onion via Tor status:", r_onion.status_code)
except Exception as e:
    print("Error:", e)
