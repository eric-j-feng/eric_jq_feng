import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import csv
import base64


SCOPES = ["https://mail.google.com/"]


def fetch_credentials():
    """Fetches user credentials for Gmail API
    Returns Credentials object
    """
    try:
        creds = None
        if os.path.exists("token.json"):
            creds = Credentials.from_authorized_user_file("token.json", SCOPES)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    "credentials.json", SCOPES
                )
                flow.redirect_uri = "urn:ietf:wg:oauth:2.0:oob"
                auth_url, _ = flow.authorization_url(prompt='consent')
                print(f"Please visit this URL to authorize the application: {auth_url}")
                code = input("Enter the authorization code here: ")
                flow.fetch_token(code=code)
                creds = flow.credentials
            with open("token.json", "w") as token:
                token.write(creds.to_json())
        return creds
    except HttpError as error:
        print(f"An error occurred while fetching credentials: {error}")
    

def fetch_message_id(service):
    """Fetches all message ids (ids) and threadIds
    Returns dictionary of all emails; id:threadId
    """
    try:
        message_dict = {}
        message_count = 0
        next_page_token = None
        while True:
            # Call the Gmail API to list messages
            results = service.users().messages().list(
                userId="me", maxResults=500, pageToken=next_page_token
            ).execute()
            messages = results.get("messages", [])
            next_page_token = results.get("nextPageToken")

            if not messages:
                print("No more messages found")
                break

            for message in messages:
                message_dict[message["id"]] = message["threadId"]

            print(f"Fetched {len(messages)} messages")
            message_count += len(messages)

            if not next_page_token:
                break

        print(f"All {message_count} messages have been stored")
        return message_dict
    except HttpError as error:
        print(f"An error occurred while listing messages: {error}")


def extract_headers(headers):
    """Extracts important headers like Subject, From, To from the message headers
    Returns dictionary of header values
    """
    headers_dict = {}
    for header in headers:
        name = header.get("name")
        value = header.get("value")
        if name in ["Subject", "From", "To", "Date"]:  # Modify as needed for other headers
            headers_dict[name] = value
    return headers_dict


def fetch_messages(service, message_dict):
    try:
        output_file = "detailed_messages.csv"
        with open(output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow([
                            "ID", "Thread ID", "Label IDs", "Snippet",
                            "History ID", "Internal Date", "Size Estimate",
                            "Subject", "From", "To", "Date", "Body"
                            ])
            for msg_id in message_dict.keys():
                message = service.users().messages().get(userId="me", id=msg_id).execute()
                if message:
                    label_ids = ", ".join(message.get("labelIds", []))
                    snippet = message.get("snippet", "")
                    history_id = message.get("historyId", "")
                    internal_date = message.get("internalDate", "")
                    size_estimate = message.get("sizeEstimate", "")

                    # Extract payload data
                    payload = message.get("payload", {})
                    headers = payload.get("headers", [])

                    # Extract headers from payload
                    headers_dict = extract_headers(headers)
                    subject = headers_dict.get("Subject", "")
                    from_header = headers_dict.get("From", "")
                    to_header = headers_dict.get("To", "")
                    date_header = headers_dict.get("Date", "")
                    
                    # Extract body from payload
                    body_data = ""
                    if "parts" in payload:
                        for part in payload["parts"]:
                            if part.get("mimeType") == "text/plain":
                                body_data = part["body"].get("data", "")
                                break
                    elif "body" in payload and payload["body"].get("data"):
                        body_data = payload["body"].get("data", "")

                    # Decode base64 body data
                    if body_data:
                        body_data = base64.urlsafe_b64decode(body_data).decode('utf-8', errors='ignore')

                    writer.writerow([
                        msg_id, message_dict[msg_id], label_ids, snippet,
                        history_id, internal_date, size_estimate, subject,
                        from_header, to_header, date_header, body_data
                                    ])
        print(f"All message details have been written to {output_file}")
    except HttpError as error:
        print(f"An error occurred: {error}")


def main():
    """Uses Gmail API to fetch all emails for user
    Displays all emails for user
    """
    creds = fetch_credentials()
    service = build("gmail", "v1", credentials=creds)
    message_dict = fetch_message_id(service)
    fetch_messages(service, message_dict)


if __name__ == "__main__":
    main()
