import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import csv

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://mail.google.com/"]


def main():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels and writes all messages to a CSV file.
    """
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

    service = build("gmail", "v1", credentials=creds)

    try:
        output_file = "messages.csv"
        message_count = 0
        with open(output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["ID", "Thread ID"])  # Write CSV headers

            # Initialize pagination
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
                    writer.writerow([message["id"], message["threadId"]])

                print(f"Fetched {len(messages)} messages")
                message_count += len(messages)

                if not next_page_token:
                    break
        print(f"All {message_count} messages have been written to {output_file}")
    except HttpError as error:
        print(f"An error occurred while listing messages: {error}")


if __name__ == "__main__":
    main()
