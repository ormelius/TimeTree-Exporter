"""
Edit a TimeTree event via API using session login and CSRF token.
"""

import argparse
import logging
import requests
from timetree_exporter.api.auth import login
from timetree_exporter.api.const import API_BASEURI, API_USER_AGENT

# Logging konfigurieren
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

def get_csrf_token(session: requests.Session, calendar_code: str, event_id: str) -> str:
    """Extrahiere CSRF-Token von der Event-Bearbeitungsseite."""
    url = f"https://timetreeapp.com/calendars/{calendar_code}/events/{event_id}/edit"
    resp = session.get(url)
    token_line = next(line for line in resp.text.splitlines() if 'csrf-token' in line)
    token = token_line.split('content="')[1].split('"')[0]
    return token

def update_event(session: requests.Session, csrf_token: str, calendar_id: str, event_id: str, calendar_code: str, payload: dict):
    """Sende PUT-Anfrage, um Event zu aktualisieren."""
    url = f"{API_BASEURI}/calendar/{calendar_id}/event/{event_id}"

    headers = {
        "Content-Type": "application/json",
        "X-Timetreea": API_USER_AGENT,
        "X-CSRF-Token": csrf_token,
        "Origin": "https://timetreeapp.com",
        "Referer": f"https://timetreeapp.com/calendars/{calendar_code}/events/{event_id}/edit",
        "User-Agent": "Mozilla/5.0",
    }

    response = session.put(url, json=payload, headers=headers)
    logger.info("Status: %s", response.status_code)
    try:
        logger.info("Response: %s", response.json())
    except Exception:
        logger.warning("No JSON-Response:")
        logger.info(response.text)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Edit a TimeTree Event")
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--calendar-id", required=True)
    parser.add_argument("--calendar-code", required=True)
    parser.add_argument("--event-id", required=True)
    parser.add_argument("--title", help="New title")
    parser.add_argument("--note", help="Note text")
    parser.add_argument("--location", help="Event location")
    args = parser.parse_args()

    payload = {}
    if args.title:
        payload["title"] = args.title
    if args.note:
        payload["note"] = args.note
    if args.location:
        payload["location"] = args.location

    session_id = login(args.email, args.password)
    session = requests.Session()
    session.cookies.set("_session_id", session_id)
    csrf = get_csrf_token(session, args.calendar_code, args.event_id)
    update_event(session, csrf, args.calendar_id, args.event_id, args.calendar_code, payload)
