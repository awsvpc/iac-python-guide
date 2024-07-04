# -*- coding: utf-8 -*-

import boto3
import json
import base64
import urllib
import urllib2
import pdb

## Please change it before uploading to lambda
AWS_REGION                             = 'ap-northeast-1'
INSPECTOR_TARGET_SERVICE_ID            = "*****"
INSPECTOR_TARGET_CLUSTER_ID            = "*****"
INSPECTOR_FINDING_NUMERIC_SEVERITY_MIN = 7.0

JIRA_BASE_URL                          = 'https://******.atlassian.net'

## Please change it before uploading to lambda
JIRA_USER_NAME                         = '*****@example.com'
JIRA_USER_PASS                         = '*****'
JIRA_AUTHORIZATION                     = 'Basic ' + base64.b64encode(JIRA_USER_NAME + ":" + JIRA_USER_PASS)
JIRA_PROJECT_KEY                        =  '*****'
JIRA_ISSUE_TYPE                        = '*****'
JIRA_ISSUE_SEARCH_JQL                  = 'project = ' + JIRA_PROJECT_KEY + ' AND "sevice id" ~ ' + INSPECTOR_TARGET_SERVICE_ID + ' AND status not in (Done, IceBox) ORDER BY cf[*****] DESC, key DESC'
JIRA_ISSUE_STOP_TRANSITION_ID           =  "**"   # ID of "action=" in JIRA "Before" link URL
JIRA_ISSUE_COMPLETE_TRANSITION_ID       =  "**"   # ID of "action=" in JIRA "Complete" link URL
JIRA_CLOSING_COMMENT                   = "This issue has already resolved."

def s3():
    return boto3.client('s3', region_name=AWS_REGION)

def get_findings():
    response = s3().get_object(Bucket=S3_BUCKET_NAME, Key=S3_OBJECT_KEY)
    body = response['Body'].read()
    all_findings = json.loads(body)
    findings = []
    for  finding  in  all_findings :
        if finding['score'] >= INSPECTOR_FINDING_NUMERIC_SEVERITY_MIN:
            findings.append(finding)

    return findings

def post_search(start_at):
    url      = JIRA_BASE_URL + '/rest/api/latest/search'
    params   = { 'jql': JIRA_ISSUE_SEARCH_JQL, 'startAt': start_at }
    body     = json.dumps(params)
    headers  = { 'Authorization': JIRA_AUTHORIZATION, 'Content-Type': 'application/json' }
    request  = urllib2.Request(url, body, headers)
    return  urllib2 . urlopen ( request )

def search_issues():
    issues = []
    start_at    = 0
    max_results = 50

    response = post_search(start_at)
    res_body = json.loads(response.read())
    issues   = issues + res_body['issues']
    while len(issues) < res_body['total']:
        start_at = res_body['startAt'] + res_body['maxResults']
        response = post_search(start_at)
        res_body = json.loads(response.read())
        issues   = issues + res_body['issues']

    return issues

def find_issue(issues, finding_id):
    for issue in issues:
        if issue["fields"]["summary"] == finding_id:
          return  issue
    return False

def generate_issue_description(finding):
    description  = "h1. Title\n"          + "{panel}\n" + finding['description']    + "{panel}\n\n"
    description += "h1. Description\n"    + "{panel}\n" + finding['description']    + "{panel}\n\n"
    description += "h1. Recommendation\n" + "{panel}\n" + finding['recommendation'] + "{panel}\n"
    return description

def generate_issue_labels(finding):
    labels = finding['labels']
    if labels[0]:
        return labels
    else:
        return []

## Please change it before uploading to lambda
def generate_issue_finding_fields(finding):
    fields = {
      'summary':           finding['id'],
      'customfield_10400': { 'value': finding['severity'] },
      'customfield_10401': finding['score'],
      'customfield_10403': finding['rule']['name'],
      'customfield_10405': INSPECTOR_TARGET_SERVICE_ID,
      'customfield_10406': INSPECTOR_TARGET_CLUSTER_ID,
      'labels':            generate_issue_labels(finding),
      'description':       generate_issue_description(finding)
    }
    return fields

def update_issue(issue, finding):
    url      = JIRA_BASE_URL + '/rest/api/latest/issue/' + issue['key']
    params   = { 'fields': generate_issue_finding_fields(finding) }
    body     = json.dumps(params)
    headers  = { 'Authorization': JIRA_AUTHORIZATION, 'Content-Type': 'application/json' }
    request  = urllib2.Request(url, body, headers)
    request.get_method = lambda: 'PUT'
    response  =  urllib2 . urlopen ( request )
    return response

def create_issue(finding):
    url      = JIRA_BASE_URL + '/rest/api/latest/issue'
    fields   = generate_issue_finding_fields(finding)
    fields['project']   = { 'key':  JIRA_PROJECT_KEY }
    fields['issuetype'] = { 'name': JIRA_ISSUE_TYPE }
    params   = { 'fields': fields }
    body     = json.dumps(params)
    headers  = { 'Authorization': JIRA_AUTHORIZATION, 'Content-Type': 'application/json' }
    request  = urllib2.Request(url, body, headers)
    response  =  urllib2 . urlopen ( request )
    issue    = json.loads(response.read())
    return  issue

def find_finding(finding, issue):
    ""
    return True

def get_issue_transitions(key):
    url      = JIRA_BASE_URL + '/rest/api/latest/issue/' + key + '/transitions'
    body     = None
    headers  = { 'Authorization': JIRA_AUTHORIZATION, 'Content-Type': 'application/json' }
    request  = urllib2.Request(url, body, headers)
    response  =  urllib2 . urlopen ( request )
    response_body = json.loads(response.read())
    return response_body['transitions']

def stop_progress_issue(key):
    return do_issue_transition(key, JIRA_ISSUE_STOP_TRANSITION_ID, {})

def complete_progress_issue(key):
    options = { 'update': { 'comment': [ { 'add': { 'body': 'JIRA_CLOSING_COMMENT' } } ] } }
    return do_issue_transition(key, JIRA_ISSUE_COMPLETE_TRANSITION_ID, options)

def do_issue_transition(key, transition_id, options):
    url      = JIRA_BASE_URL + '/rest/api/latest/issue/' + key + '/transitions'
    params   = { 'transition': { 'id': transition_id } }
    params.update(options)
    body     = json.dumps(params)
    headers  = { 'Authorization': JIRA_AUTHORIZATION, 'Content-Type': 'application/json' }
    request  = urllib2.Request(url, body, headers)
    return  urllib2 . urlopen ( request )

def close_issue(key):
    transitions = get_issue_transitions(key)

    complete_transition = None
    for transition in transitions:
        if  transition [ 'name' ].encode ( ' utf-8' ) ==  'done' :
            complete_transition = transition
    
    if not complete_transition:
        stop_progress_issue(key)

    complete_progress_issue(key)
    return True

# JIRA課題 管理
# * Vulnerability detected in Inspector && in JIRA => JIRA issue updated
# * Vulnerability detected by Inspector && Not in JIRA => Create JIRA issue
# * Vulnerability not detected by Inspector && In JIRA => JIRA issue closed
def update_issues(findings, issues):
    for finding in findings:
        issue = find_issue(issues, finding["id"])
        if issue:
            update_issue(issue, finding)
        else:
            create_issue(finding)

    for issue in issues:
        finding = find_finding(finding, issue)
        if not finding:
            clouse_issue(issue["key"])

    return ""

def lambda_handler(event, context):
    global S3_BUCKET_NAME
    global S3_OBJECT_KEY
    S3_BUCKET_NAME = event['Records'][0]['s3']['bucket']['name']
    S3_OBJECT_KEY  = event['Records'][0]['s3']['object']['key']

    findings = get_findings()
    issues   = search_issues()
    update_issues(findings, issues)

    return S3_OBJECT_KEY
