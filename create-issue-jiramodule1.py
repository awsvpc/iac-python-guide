import requests
from requests.auth import HTTPBasicAuth
import json

def create_jira_task(server, username, password, project_key, task_name, task_type, description, story_points, dashboard, link, assignee, reporter):
    url = f"{server}/rest/api/2/issue"
    
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    # Prepare the payload
    payload = {
        "fields": {
            "project": {
                "key": project_key
            },
            "summary": task_name,
            "description": description,
            "issuetype": {
                "name": task_type
            },
            "assignee": {
                "name": assignee
            },
            "reporter": {
                "name": reporter
            }
        }
    }
    
    # Add optional fields if provided
    if story_points:
        payload["fields"]["customfield_10004"] = float(story_points)  # Update with the actual custom field ID for story points
    if dashboard:
        payload["fields"]["customfield_10007"] = dashboard  # Update with the actual custom field ID for dashboard link
    if link:
        payload["fields"]["customfield_10010"] = link  # Update with the actual custom field ID for link
    
    # Make the API request
    response = requests.post(
        url,
        data=json.dumps(payload),
        headers=headers,
        auth=HTTPBasicAuth(username, password)
    )
    
    # Check the response
    if response.status_code == 201:
        task_id = response.json().get('key')
        print(f'Task created successfully. Task ID: {task_id}')
    else:
        print(f'Failed to create task. Status Code: {response.status_code}')
        print(f'Response: {response.text}')

if __name__ == "__main__":
    # Collect inputs
    server = input("Enter Jira server URL (e.g., https://your-domain.atlassian.net): ")
    username = input("Enter Jira username: ")
    password = input("Enter Jira password: ")  # For security reasons, consider using getpass.getpass for hidden input
    project_key = input("Enter Jira project key: ")
    task_name = input("Enter task name: ")
    task_type = input("Enter task type (e.g., Story, Task, Bug): ")
    description = input("Enter task description: ")
    story_points = input("Enter story points (leave blank if not applicable): ")
    dashboard = input("Enter dashboard link (leave blank if not applicable): ")
    link = input("Enter link (leave blank if not applicable): ")
    assignee = input("Enter assignee's username: ")
    reporter = input("Enter reporter's username: ")
    
    # Create the task
    create_jira_task(server, username, password, project_key, task_name, task_type, description, story_points, dashboard, link, assignee, reporter)
