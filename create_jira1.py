import os
from jira import JIRA
def create_ticket():
	try:
		jira_connection = JIRA(basic_auth=(os.environ['JIRA_EMAIL'], os.environ['JIRA_TOKEN']), server=os.environ['JIRA_SERVER_URL'])

		issue_dict = {
			'project': {'key': os.environ['JIRA_ORG_ID']},
			'summary': os.environ['JIRA_SUMMARY'],
			'description': os.environ['JIRA_DESCRIPTION'],
			'issuetype': {'name': 'Task'}

			}

		new_issue = jira_connection.create_issue(fields=issue_dict)
		print(f'{new_issue.key}')
		return (f'{new_issue.key}')
	except Exception as e:
		print(f'Error while creating Jira Ticket: {e}')
		return ''
if __name__ == '__main__':
	create_ticket()


#############
link_issue.py
 def link_issue(self,inwardIssue):
        res = self.jira.create_issue_link("Related",inwardIssue,self.new_issue)
        print(res) # <Response [201]>

#############
init jira
# install jira
# pipenv install jira 
 
from jira import JIRA
jira = JIRA(os.getenv("jira_url"),basic_auth=(os.getenv('username'),os.getenv('password')))
################
create issue
from datetime import datetime,timedelta
import os
 
def create_issues(project,assignee,summary,description,issuetype,**kw):
        issue_dict = {
            "project":{"key":project},
            "assignee":{"name":assignee},
            "summary":summary,
            "description":description,
            "issuetype":{"name":issuetype},
            "customfield_10001": {
                "value": "3 - Medium"
            },
            "customfield_10024": datetime.strftime(datetime.now() + timedelta(days=30),"%Y-%m-%d")
        }
        if kw:
            issue_dict.update(kw)
        
        new_issue = jira.create_issue(fields=issue_dict) # jira is the result of init 
        print(new_issue) # print issue number but it is issue object

############

close issue
 def close_issue(self):
        res = self.jira.transition_issue(self.new_issue,"2891",fields={"assignee":{"name":"+close_folder"},"resolution":{"name":"Completed"}},comment="close the issue")
        print(res)

#########
attach file
 def attach_file(self,file):
        with open(file, 'rb') as f:
            self.jira.add_attachment(issue=self.new_issue, attachment=f,filename="test")

###########
add to current sprint
def add_to_current_spring(self):
        res = self.jira.sprints(437)
        #print(dir(res[0]))
        #print(res[0].state)
        for sprint in res:
            if sprint.state == "ACTIVE":
                print(isinstance(sprint.id,int))
                print(self.new_issue.key)
                res = self.jira.add_issues_to_sprint(sprint_id=sprint.id,issue_keys=[self.new_issue.key])
                print(res)
############3

jira _release

#! /usr/bin/env python3
import sys
import argparse
import json
import netrc
import textwrap
import urllib.parse
import urllib.request
import urllib.error

from base64 import b64encode

netrz = netrc.netrc()

jira_creds = None
jira_host = None

# bb_host = None
# bb_creds = None


def main():
    global jira_creds, jira_host
    args = parse_args()
    jira_host = args.jira
    jira_creds = netrz.authenticators(args.jira)
    if jira_creds is None:
        raise LookupError(f'could not locate {args.jira} credentials from your $HOME/.netrc file for {args.jira}')

    # bb_host = args.b
    # bb_creds = netrz.authenticators(args.b)
    # if bb_creds is None:
    #     raise LookupError(f'could not locate {args.b} credentials from your $HOME/.netrc file for {args.b}')

    try:
        repo_info = fetch_issues_for_release(args.p, args.jira_release[0])

        if 'json' == args.output:
            print(json.dumps(repo_info, indent=True))
        else:
            for repo_name, issues in repo_info.items():
                print(f'# {repo_name}')
                print(f'git fetch')
                for issue_key, v in issues.items():
                    short_summary = textwrap.shorten(v["summary"], width=72)
                    print(f'# {issue_key} {short_summary}')
                    for branch_name in v['branches']:
                        print(f'git merge origin/{branch_name} # {issue_key}')
                    for commit_id in v['commits']:
                        print(
                            f"git merge-base --is-ancestor {commit_id} HEAD || echo 'error for {commit_id}@{repo_name} of {issue_key}'")
    except urllib.error.HTTPError as error:
        if 400 == error.code:
            print("Bad Request, check Release Version, or Project Key")
        else:
            raise error


def fetch_issues_for_release(project, release):
    repos = {}

    def issue_cb(results, response):
        issue_count = len(results["issues"])
        for issue in results["issues"]:
            issue_id = issue["id"]
            issue_key = issue["key"]
            deets_paload = get_dev_details_payload(issue_id)
            jh = {'Content-Type': 'application/json'}
            dev_details = jira_request("/jsw/graphql?operation=DevDetailsDialog", data=deets_paload, headers=jh).json()

            for it in dev_details['data']['developmentInformation']['details']['instanceTypes']:
                for repo in it['repository']:
                    repo_name = repo['name']
                    if repo_name not in repos:
                        repos[repo_name] = {}
                    if issue_key not in repos[repo_name]:
                        repos[repo_name][issue_key] = {
                            'summary': issue['fields']['summary'],
                            'branches': [], 'commits': []
                        }
                    for branch in repo['branches']:
                        branch_name = branch['name']
                        repos[repo_name][issue_key]['branches'].append(branch_name)
                    for branch in repo['branches']:
                        branch_name = branch['name']
                    for commit in repo['commits']:
                        commit_id = commit['id']
                        repos[repo_name][issue_key]['commits'].append(commit_id)

        return issue_count

    jql = f'project = "{project}" AND development[commits].all > 0 and fixVersion = "{release}"'
    paged_jira_request(issue_cb, '/rest/api/3/search', json={'maxResults': 10, 'jql': jql})

    return repos


def parse_args():

    help_text = 'Confirm a set of repo branches against a Jira release'

    parser = argparse.ArgumentParser(description=help_text)
    parser.add_argument('jira_release', nargs=1, help='jira release')
    parser.add_argument('-p', help='Jira Project Key', required=True)
    parser.add_argument('--jira', nargs='?', help='Jira endpoint, e.g. example.atlassian.net',
                        default='example.atlassian.net')
    parser.add_argument('-b', nargs='?', help='Bitbucket endpoint, e.g. api.bitbucket.org',
                        default='api.bitbucket.org')
    parser.add_argument('--output', help='output', choices=['json', 'shell'], default='shell')

    return parser.parse_args()


def basic_auth(creds):
    return 'Basic ' + b64encode((creds[0] + ':' + creds[2]).encode('utf-8')).decode('utf-8')


def request(method, uri, data=None, json=None, params=None, headers=None, auth=None):
    bindata = None
    url = f'{uri}'
    hdrs = {**headers} if headers else {}
    if 'get' == method or 'delete' == method:
        if params:
            url += '?' + urllib.parse.urlencode(params)
    else:
        bindata = None
        if json:
            if 'Content-Type' not in hdrs:
                hdrs['Content-Type'] = 'application/json'
            bindata = globals()['json'].dumps(json).encode('utf-8')
        elif data:
            bindata = data if type(data) == bytes else data.encode('utf-8')
        else:
            raise Exception("data or json param required")

    if auth:
        creds = (auth[0], None, auth[1])
        hdrs['Authorization'] = basic_auth(creds)

    req = urllib.request.Request(url, data=bindata, headers=hdrs, method=method.upper())
    with urllib.request.urlopen(req) as resp:
        return JsonResponse(resp)


class JsonResponse:
    def __init__(self, response):
        self.data = response.read().decode('utf-8')
        self.status_code = response.status
        self.headers = response.headers
        self.url = response.url

    def json(self):
        return json.loads(self.data)


def jira_request(path, data=None, json=None, params=None, method='post', **kwargs):
    global jira_creds, jira_host
    jira_up = (jira_creds[0], jira_creds[2])
    response = request(
        method, f"https://{jira_host}{path}", data=data, json=json, **kwargs, params=params, auth=jira_up)

    if response.status_code >= 400:
        raise Exception(f"Jira responded with status code: {response.status_code}")

    return response


def paged_jira_request(cb, path, json=None, params=None, method='post', **kwargs):
    global jira_creds, jira_host
    jira_up = (jira_creds[0], jira_creds[2])

    start_at = 0
    done = False

    while not done:
        if json:
            json["startAt"] = start_at
        else:
            if params:
                params['startAt'] = start_at
                if 'maxResults' not in params:
                    params['maxResults'] = 100
            else:
                params = {'startAt': start_at, 'maxResults': 100}

        response = request(
            method, f"https://{jira_host}{path}", json=json, **kwargs, params=params, auth=jira_up)

        if response.status_code >= 400:
            raise Exception(f"Jira responded with status code: {response.status_code}")

        results = response.json()

        start_at += cb(results, response)

        if start_at >= results['total']:
            done = True

# HACK
# got this from browser Dev Tools, Bitbucket uses GraphQL to load bitbucket info related to jira issue
# seems like it might eventually become a public api since it is not yet marked with internal path
# I copied at pasted the GraphQL payload as is, and mutate it just enough, to change the issue_id


def get_dev_details_payload(issue_id):
    data = '{"operationName":"DevDetailsDialog","query":"\\n    query DevDetailsDialog ($issueId: ID\u0021) {\\n        developmentInformation(issueId: $issueId){\\n            \\n    details {\\n        instanceTypes {\\n            id\\n            name\\n            type\\n            typeName\\n            isSingleInstance\\n            baseUrl\\n            devStatusErrorMessages\\n            repository {\\n                name\\n                avatarUrl\\n                description\\n                url\\n                parent {\\n                    name\\n                    url\\n                }\\n                branches {\\n        name\\n        url\\n        createReviewUrl\\n        createPullRequestUrl\\n        lastCommit {\\n            url\\n            displayId\\n            timestamp\\n        }\\n        pullRequests {\\n            name\\n            url\\n            status\\n            lastUpdate\\n        }\\n        reviews {\\n            state\\n            url\\n            id\\n        }\\n    }\\n                commits{\\n        id\\n        displayId\\n        url\\n        createReviewUrl\\n        timestamp\\n        isMerge\\n        message\\n        author {\\n          name\\n          avatarUrl\\n        }\\n        files{\\n          linesAdded\\n          linesRemoved\\n          changeType\\n          url\\n          path\\n        }\\n        reviews{\\n          id\\n          url\\n          state\\n        }\\n    }\\n                pullRequests {\\n        id\\n        url\\n        name\\n        branchName\\n        branchUrl\\n        lastUpdate\\n        status\\n        author {\\n          name\\n          avatarUrl\\n        }\\n        reviewers{\\n          name\\n          avatarUrl\\n          isApproved\\n        }\\n    }\\n            }\\n            danglingPullRequests {\\n        id\\n        url\\n        name\\n        branchName\\n        branchUrl\\n        lastUpdate\\n        status\\n        author {\\n          name\\n          avatarUrl\\n        }\\n        reviewers{\\n          name\\n          avatarUrl\\n          isApproved\\n        }\\n    }\\n            buildProviders {\\n          id\\n          name\\n          url\\n          description\\n          avatarUrl\\n          builds {\\n            id\\n            buildNumber\\n            name\\n            description\\n            url\\n            state\\n            testSummary {\\n              totalNumber\\n              numberPassed\\n              numberFailed\\n              numberSkipped\\n            }\\n            lastUpdated\\n            references {\\n              name\\n              uri\\n            }\\n          }\\n        }\\n         }\\n         deploymentProviders {\\n          id\\n          name\\n          homeUrl\\n          logoUrl\\n          deployments {\\n            displayName\\n            url\\n            state\\n            lastUpdated\\n            pipelineId\\n            pipelineDisplayName\\n            pipelineUrl\\n            environment {\\n                id\\n                type\\n                displayName\\n            }\\n          }\\n        }\\n         featureFlagProviders {\\n        id\\n        createFlagTemplateUrl\\n        linkFlagTemplateUrl\\n        featureFlags {\\n            id\\n            key\\n            displayName\\n            providerId\\n            details{\\n                url\\n                lastUpdated\\n                environment{\\n                    name\\n                    type\\n                }\\n                status{\\n                enabled\\n                defaultValue\\n                rollout{\\n                    percentage\\n                    text\\n                    rules\\n                }\\n            }\\n        }\\n    }\\n}\\n         remoteLinksByType {\\n        providers {\\n            id\\n            name\\n            homeUrl\\n            logoUrl\\n            documentationUrl\\n            actions {\\n                id\\n                label {\\n                    value\\n                }\\n                templateUrl\\n            }\\n        }\\n        types {\\n            type\\n            remoteLinks {\\n                id\\n                providerId\\n                displayName\\n                url\\n                type\\n                description\\n                status {\\n                    appearance\\n                    label\\n                }\\n                actionIds\\n                attributeMap {\\n                    key\\n                    value\\n                }\\n            }\\n        }\\n    }\\n         \\n    embeddedMarketplace {\\n        shouldDisplayForBuilds,\\n        shouldDisplayForDeployments,\\n        shouldDisplayForFeatureFlags\\n      }\\n\\n    }\\n\\n        }\\n    }","variables":{"issueId":"' + issue_id + '"}}'
    return data


# def bb_request(path, data=None, json=None, params=None, method='get', **kwargs):
#     global bb_creds, bb_host
#     bb_up = (bb_creds[0], bb_creds[2])
#     response = request(
#         method, f"https://{bb_host}{path}", data=data, json=json, **kwargs, params=params, auth=bb_up)

#     if response.status_code >= 400:
#         raise Exception(f"BitBucket responded with status code: {response.status_code}")

#     return response


if __name__ == '__main__':
    main()
#############

create issue with attachment

from jira import JIRA
import click

ISSUE_SUMMARY = "TEST SUMMARY from kittoh"
ISSUE_DESCRIPTION = """TEST
1.
2.
3.
"""

@click.command(
    short_help='Open a JIRA ticket with your report findings.'
)
@click.option(
    '--server',
    # default="https://jira.atlassian.com",
    required=True,
    type=str,
    help='The JIRA server.'
)
@click.option(
    '--project',
    required=True,
    help="The 3-4 character JIRA Project key."
)
@click.option(
    '--attachment_path',
    help='File path of the attachment.'
)

def open_jira_ticket(project, server, attachment_path):
    jira=jira_login(server)
    issue=jira.create_issue(
        project = project,
        summary = ISSUE_SUMMARY,
        description = ISSUE_DESCRIPTION,
        issuetype = {
            'name': 'Bug'
        }
    )

    # with open('report.txt', 'rb') as f:
    #     jira.add_attachment(issue=issue, attachment=f)
    #     f.close()
    attachment_item = open(attachment_path, 'rb')
    jira.add_attachment(issue=issue, attachment=attachment_item)
    
    print("Issue opened and attachments added. Metadata:")
    print(f"\tIssue ID: {issue.id}")
    print(f"\tIssue Key: {issue.key}")
    print(f"Uploaded: {attachment_item}")

def jira_login(server):

    import os
    email = os.getenv("JIRA_EMAIL")
    api_key = os.getenv("JIRA_API_KEY")
    options = {
        "server": server,
    }
    # Supporting HTTP BASIC Auth right now.
    # You can extend this script to support Cookie-based, OAuth or Kerberos."""
    # Docs: https://jira.readthedocs.io/en/master/examples.html#authentication
    auth_jira = JIRA(
        options=options,
        basic_auth=(
            email,
            api_key
        )
    )
    return auth_jira


if __name__ == '__main__':
    open_jira_ticket()

#################

test jira

#!/usr/bin/python

from jira.client import JIRA
import argparse
import jira.client

parser = argparse.ArgumentParser(description='Automation Jira cards')
parser.add_argument('--key', help='add jira API key')
parser.add_argument('--email', help='Your Jira email')
parser.add_argument('--server', help='Your server URL', required=True)
#parser.add_argument('--issue', help='Name or ID of Issue')
#parser.add_argument('--issueType', help='Issue type, e.g Bug')
#parser.add_argument('--priority', help='Priority of issue, e.g HIGH')

args = parser.parse_args()

jira = JIRA(options={'server': args.server}, basic_auth=(args.email, args.key))

projects = jira.projects()
jra = jira.project('SAP')
print(jra.name)
print(jra.lead.displayName)
#issue_dict = {
#    'project': {'id':u'10328'},
#    'summary': 'New issue from jira-python',
#    'description': 'Look into this one',
#    'issuetype': {'id':u'10004'},
#    'customfield_10208' : '10478',
#    'customfield_10115' : '10312'
#    }
#new_issue = jira.create_issue(fields=issue_dict)

new_issue = jira.create_issue(project='10328', summary='New issue from jira-python', description='Look into this one', issuetype={'id': '10004'})
##############

github to jira tickets

"""
Exports Issues from a specified repository to a CSV file and creates corresponding tickets in JIRA.
Uses basic authentication (Github username + password) to retrieve Issues
from a repository that username has access to. Supports Github API v3.
Use the following gist as config for this script: https://gist.github.com/atharvai/16996fbb73442f8a1cfb5bffb11c412e
"""
import csv
import requests
import json
import sys
from jira import JIRA
from migrate_config import GITHUB_AUTH, JIRA_SERVER, JIRA_AUTH, JIRA_PROJECT, REPO, JIRA_TICKET_TYPE, user_map, \
    labels_map

ISSUES_FOR_REPO_URL = 'https://api.github.com/repos/%s/issues?state=open' % REPO

try:
    jira = JIRA(server=JIRA_SERVER, basic_auth=JIRA_AUTH, validate=False,
                options={'rest_api_version': 'latest', 'verify': False})
except Exception as e:
    print(e.message)
    sys.exit(1)


def write_issues_to_csv(rows):
    csvfile = '%s-issues.csv' % (REPO.replace('/', '-'))
    with open(csvfile, 'wb') as f:
        csvout = csv.DictWriter(f, rows[0].keys())
        csvout.writeheader()
        csvout.writerows(rows)


def github_get_issues(url):
    r = requests.get(url, auth=GITHUB_AUTH)
    issues_only = [i for i in r.json() if i['state'] == 'open' and 'pull_request' not in i]
    issues_rest = github_get_further_issues(r)
    return issues_only + issues_rest


def github_get_further_issues(orig_response):
    # more pages? examine the 'link' header returned
    all_issues = []
    if 'link' in orig_response.headers:
        pages = dict(
            [(rel[6:-1], url[url.index('<') + 1:-1]) for url, rel in
             [link.split(';') for link in
              orig_response.headers['link'].split(',')]])
        while 'last' in pages and 'next' in pages:
            issues = get_issues(pages['next'])
            all_issues = all_issues + issues
            if pages['next'] == pages['last']:
                break
    return all_issues


def jira_create_ticket(github_issue):
    description = github_issue['body'] + '\n\nref: ' + github_issue['url']
    github_labels = [l['name'] for l in github_issue['labels']]
    jira_labels = [labels_map[l] for l in github_labels if l in labels_map]

    ticket = {'project': JIRA_PROJECT,
              'issuetype': {'name': JIRA_TICKET_TYPE},
              'summary': github_issue['title'],
              'description': description,
              'labels': jira_labels,
              }

    reporter = user_map[github_issue['user']['login']] if github_issue['user'] else None
    if reporter:
        ticket['reporter'] = {'name': reporter}
    assignee = user_map[github_issue['assignee']['login']] if github_issue['assignee'] else None
    if assignee:
        ticket['assignee'] = {'name': assignee}

    new_ticket = jira.create_issue(ticket)
    return new_ticket


def jira_import_issues(github_issues_list):
    issue_ticket_map = {}
    for github_issue in github_issues_list:
        ticket = jira_create_ticket(github_issue)
        issue_ticket_map[github_issue['number']] = ticket.key
    print(json.dumps(issue_ticket_map, indent=2))
    return issue_ticket_map


def add_jira_ref_to_github_issue(issue_ticket_map):
    issue_url_base = 'https://api.github.com/repos/{repo}/issues/{issue_num}'
    comment_url_base = 'https://api.github.com/repos/{repo}/issues/{issue_num}/comments'
    for issue, key in issue_ticket_map.iteritems():
        print('Github: {}\tJIRA: {}'.format(issue, key))
        comment_url = comment_url_base.format(repo=REPO, issue_num=issue)
        comment = {'body': 'Tracked in: {}{}'.format(JIRA_SERVER + '/projects/' + JIRA_PROJECT + '/issues/', key)}
        resp = requests.post(comment_url, json=comment, auth=GITHUB_AUTH)
        if resp.status_code == 201:
            print('comment added to github issue')
        else:
            print('failed to add comment to github issue')
        issue_url = issue_url_base.format(repo=REPO, issue_num=issue)
        body = {'state': 'closed'}
        resp = requests.post(issue_url, json=body, auth=GITHUB_AUTH)
        if resp.status_code == 200:
            print('github issue closed')
        else:
            print('failed to close github issue')


if __name__ == '__main__':
    issues = github_get_issues(ISSUES_FOR_REPO_URL)
    write_issues_to_csv(issues)
    issue_ticket_map = jira_import_issues(issues)
    add_jira_ref_to_github_issue(issue_ticket_map)
