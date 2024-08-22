import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import csv

# If modifying these scopes, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def main():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels and writes 100 messages to a CSV file.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first time.
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json", SCOPES
            )
            flow.redirect_uri = "urn:ietf:wg:oauth:2.0:oob"

            # Instead of using run_local_server, print the auth URL and handle the code manually
            auth_url, _ = flow.authorization_url(prompt='consent')

            print(f"Please visit this URL to authorize the application: {auth_url}")

            # Manually input the code from the URL
            code = input("Enter the authorization code here: ")

            flow.fetch_token(code=code)
            creds = flow.credentials

        # Save the credentials for the next run
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    service = build("gmail", "v1", credentials=creds)

    try:
        # Call the Gmail API to list labels
        results = service.users().labels().list(userId="me").execute()
        labels = results.get("labels", [])

        if not labels:
            print("No labels found.")
        else:
            print("Labels:")
            for label in labels:
                print(label["name"])

    except HttpError as error:
        print(f"An error occurred while listing labels: {error}")

    try:
        # Call the Gmail API to list messages
        results = service.users().messages().list(userId="me", maxResults=100).execute()
        messages = results.get("messages", [])

        if not messages:
            print("No messages found")
            return

        output_file = "messages.csv"
        with open(output_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["ID", "Thread ID"])  # Write CSV headers

            for message in messages:
                writer.writerow([message["id"], message["threadId"]])

        print(f"{len(messages)} messages have been written to {output_file}")

    except HttpError as error:
        print(f"An error occurred while listing messages: {error}")


if __name__ == "__main__":
    main()
