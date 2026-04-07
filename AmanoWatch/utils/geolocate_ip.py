import geoip2.database
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "utils" / "GeoLite2-Country.mmdb"

def search_ip(ip):
    with geoip2.database.Reader(DB_PATH) as reader:
        response = reader.country(ip)
        
        return response.country.name
    