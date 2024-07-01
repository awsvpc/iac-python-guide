from jira import JIRA
import getpass

# Function to create a Jira task
def create_jira_task(server, username, password, project_key, task_name, task_type, description, story_points, dashboard, link, assignee, reporter):
    # Connect to Jira
    jira_options = {'server': server}
    jira = JIRA(options=jira_options, basic_auth=(username, password))
    
    # Define the task fields
    issue_dict = {
        'project': {'key': project_key},
        'summary': task_name,
        'description': description,
        'issuetype': {'name': task_type},
        'customfield_10004': story_points,  # Change this if your Jira uses a different field for story points
        'customfield_10007': dashboard,  # Change this if your Jira uses a different field for dashboard link
        'customfield_10010': link,  # Change this if your Jira uses a different field for link
        'assignee': {'name': assignee},
        'reporter': {'name': reporter}
    }
    
    # Create the task
    issue = jira.create_issue(fields=issue_dict)
    
    # Check if the task was created successfully
    if issue:
        print(f'Task created successfully. Task ID: {issue.key}')
    else:
        print('Failed to create task.')

if __name__ == "__main__":
    # Collect inputs
    server = input("Enter Jira server URL (e.g., https://your-domain.atlassian.net): ")
    username = input("Enter Jira username: ")
    password = getpass.getpass("Enter Jira password: ")
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
