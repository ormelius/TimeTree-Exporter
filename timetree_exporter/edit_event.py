"""
Edit a TimeTree event via API using session login and CSRF token.
"""

import argparse
import logging
import requests
import os

from timetree_exporter.api.auth import login
from timetree_exporter.api.const import API_BASEURI, API_USER_AGENT

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger(__name__)

def get_csrf_token(session: requests.Session, calendar_code: str, event_id: str) -> str:
    """Extract CSRF tokens from the event processing page"""
    url = f"https://timetreeapp.com/calendars/{calendar_code}/events/{event_id}/edit"
    resp = session.get(url)
    try:
        token_line = next(line for line in resp.text.splitlines() if 'csrf-token' in line)
        token = token_line.split('content="')[1].split('"')[0]
        return token
    except StopIteration:
        logger.error("CSRF-Token nicht gefunden. HTML:\n%s", resp.text[:500])
        raise

def update_event(session: requests.Session, csrf_token: str, calendar_id: str, event_id: str, calendar_code: str, payload: dict):
    """Send PUT request to update event"""
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
    parser = argparse.ArgumentParser(description="Edit a TimeTree event via API.")
    parser.add_argument("--email", help="TimeTree login email (or use TIMETREE_EMAIL env)")
    parser.add_argument("--password", help="TimeTree password (or use TIMETREE_PASSWORD env)")
    parser.add_argument("--calendar-id", required=True, help="Numeric calendar ID (e.g. 99848805)")
    parser.add_argument("--calendar-code", required=True, help="Calendar code string (e.g. iiz4fJaxSPHz)")
    parser.add_argument("--event-id", required=True, help="Event ID to edit")
    parser.add_argument("--title", help="New event title")
    parser.add_argument("--note", help="New note content")
    parser.add_argument("--location", help="New event location")
    parser.add_argument("--location-lat", type=float, help="Latitude of location")
    parser.add_argument("--location-lon", type=float, help="Longitude of location")
    args = parser.parse_args()

    # Get login credentials from args or environment
    email = args.email or os.environ.get("TIMETREE_EMAIL")
    password = args.password or os.environ.get("TIMETREE_PASSWORD")

    if not email or not password:
        logger.error("Email or password missing. Please provide via argument or TIMETREE_EMAIL / TIMETREE_PASSWORD environment variables.")
        exit(1)

    payload = {}
    if args.title:
        payload["title"] = args.title
    if args.note:
        payload["note"] = args.note
    if args.location:
        payload["location"] = args.location
    if args.location_lat:
        payload["location_lat"] = args.location_lat
    if args.location_lon:
        payload["location_lon"] = args.location_lon

    session_id = login(email, password)
    session = requests.Session()
    session.cookies.set("_session_id", session_id)
    csrf = get_csrf_token(session, args.calendar_code, args.event_id)
    update_event(session, csrf, args.calendar_id, args.event_id, args.calendar_code, payload)
