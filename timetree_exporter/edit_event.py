"""
Edit a TimeTree event via API using session login and CSRF token.
"""

import argparse
import logging
import os
import re
import subprocess

import requests

from timetree_exporter.api.auth import login
from timetree_exporter.api.const import API_BASEURI, API_USER_AGENT

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger(__name__)


def get_csrf_token(session: requests.Session, calendar_code: str, event_id: str) -> str:
    """Extract CSRF token from the event edit page."""
    url = f"https://timetreeapp.com/calendars/{calendar_code}/events/{event_id}/edit"
    resp = session.get(url)
    try:
        token_line = next(line for line in resp.text.splitlines() if "csrf-token" in line)
        match = re.search(r'content="([^"]+)"', token_line)
        if not match:
            raise ValueError("CSRF token not found in meta tag")
        return match.group(1)
    except StopIteration:
        logger.error("CSRF token not found. HTML:\n%s", resp.text[:500])
        raise


def update_event(
    session: requests.Session,
    csrf_token: str,
    calendar_id: str,
    event_id: str,
    calendar_code: str,
    payload: dict,
) -> int:
    """Send PUT request to update event. Returns HTTP status code."""
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
        logger.warning("No JSON response:")
        logger.info(response.text)

    return response.status_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Edit a TimeTree event via API.")
    parser.add_argument("--email", help="TimeTree login email (or use TIMETREE_EMAIL env)")
    parser.add_argument("--calendar-id", required=True, help="Numeric calendar ID (e.g. 99848805)")
    parser.add_argument("--calendar-code", required=True, help="Calendar code string (e.g. iiz4fJaxSPHz)")
    parser.add_argument("--event-id", required=True, help="Event ID to edit")
    parser.add_argument("--export-script", help="Path to export script to run after update", default=None)
    parser.add_argument("--title", help="New event title")
    parser.add_argument("--note", help="New note content")
    parser.add_argument("--location", help="New event location")
    parser.add_argument("--location-lat", type=float, help="Latitude of location")
    parser.add_argument("--location-lon", type=float, help="Longitude of location")
    args = parser.parse_args()

    email = args.email or os.environ.get("TIMETREE_EMAIL")
    password = os.environ.get("TIMETREE_PASSWORD")

    if not email or not password:
        logger.error(
            "Email or password missing. "
            "Use --email or TIMETREE_EMAIL env var for email, "
            "and TIMETREE_PASSWORD env var for password."
        )
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
    status = update_event(session, csrf, args.calendar_id, args.event_id, args.calendar_code, payload)

    if status == 200:
        logger.info("Event successfully updated.")
        if args.export_script:
            try:
                subprocess.run([args.export_script], check=True)
                logger.info("Export script executed successfully.")
            except subprocess.CalledProcessError as e:
                logger.error("Export script failed: %s", e)
        else:
            logger.info("No export script specified, skipping.")
    else:
        logger.error("Event update failed with status %d", status)
