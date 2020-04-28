"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_ip_1() called')

    # collect data for 'geolocate_ip_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_2:artifact:*.cef.sourceAddress', 'filtered-data:filter_1:condition_2:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=filter_2, name="geolocate_ip_1")

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_iso_code", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_iso_code", "==", ""],
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ip_reputation_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:geolocate_ip_1:action_result.parameter.ip", "filtered-data:filter_2:condition_1:geolocate_ip_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'ip': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act("ip reputation", parameters=parameters, assets=['virustotal'], callback=join_format_1, name="ip_reputation_1")

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Add {0} to internal ranges?"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_2:geolocate_ip_1:action_result.parameter.ip",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types, callback=add_list_1)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    parameters.append({
        'body': formatted_data_1,
        'from': "security@phantom.us",
        'attachments': "",
        'to': "niroy@splunk.com",
        'cc': "",
        'bcc': "",
        'headers': "",
        'subject': "Results of IP threat intel",
    })
    
    phantom.debug(parameters)

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_1")

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "in", "custom_list:internal_ip_list"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_format_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:internal_ip_list"],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        geolocate_ip_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def add_list_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_list_1() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_2:geolocate_ip_1:action_result.parameter.ip"])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.add_list("internal_ip_list", filtered_results_item_1_0)
    join_format_1(container=container)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """The following IPs were Internal and in the list:
{0}

The following IPs were determined to be internal and prompted to be added to the list:
{1}

The following IPs were investigated and may be malicious, follow up in mission control:
{2}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:artifact:*.cef.sourceAddress",
        "filtered-data:filter_2:condition_2:geolocate_ip_1:action_result.parameter.ip",
        "ip_reputation_1:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    send_email_1(container=container)

    return

def join_format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_format_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_format_1_called'):
        return

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'ip_reputation_1' ]):
        
        # save the state that the joined function has now been called
        phantom.save_run_data(key='join_format_1_called', value='format_1')
        
        # call connected block "format_1"
        format_1(container=container, handle=handle)
    
    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return