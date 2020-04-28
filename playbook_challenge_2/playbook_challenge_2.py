"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'url_reputation_1' block
    url_reputation_1(container=container)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """The URL was properly blocked

{0}"""

    # parameter list for template variable replacement
    parameters = [
        "url_reputation_1:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    send_email_1(container=container)

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:artifact:*.cef.fromEmail', 'url_reputation_1:artifact:*.id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'send_email_1' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'body': formatted_data_1,
                'to': inputs_item_1[0],
                'from': "security@phantom.us",
                'attachments': "",
                'subject': "Unblock Request Rejected",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act("send email", parameters=parameters, assets=['smtp'], callback=join_set_status_4, name="send_email_1")

    return

def send_email_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_4() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_4' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:artifact:*.cef.fromEmail', 'url_reputation_1:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'send_email_4' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'body': "Access to that URL has been denied by the security team",
                'to': inputs_item_1[0],
                'from': "security@phantom.us",
                'attachments': "",
                'subject': "Unblock Request Rejected",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act("send email", parameters=parameters, assets=['smtp'], callback=join_set_status_4, name="send_email_4")

    return

def send_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_2' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:artifact:*.cef.fromEmail', 'url_reputation_1:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'send_email_2' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'body': "Your request is being processed ",
                'to': inputs_item_1[0],
                'from': "security@phantom.us",
                'attachments': "",
                'subject': "Unblock Request Processing",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="send_email_2")

    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('url_reputation_1() called')

    # collect data for 'url_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("url reputation", parameters=parameters, assets=['virustotal'], callback=decision_1, name="url_reputation_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.summary.positives", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    prompt_1(action=action, success=success, container=container, results=results, handle=handle)

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """unblock?"""

    # response options
    options = {
        "type": "list",
        "choices": [
            "Yes",
            "No",
        ]
    }

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=1, name="prompt_1", options=options, callback=decision_2)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        allow_url_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.status", "==", "failed"],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        send_email_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.response", "==", "No"],
        ])

    # call connected blocks if condition 3 matched
    if matched_artifacts_3 or matched_results_3:
        send_email_4(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def allow_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('allow_url_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'allow_url_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.parameter.url', 'url_reputation_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'allow_url_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("allow url", parameters=parameters, assets=['blue_coat'], callback=allow_url_1_callback, name="allow_url_1")

    return

def allow_url_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('allow_url_1_callback() called')
    
    disallow_url_1(action=action, success=success, container=container, results=results, handle=handle)
    send_email_3(action=action, success=success, container=container, results=results, handle=handle)

    return

def send_email_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_3() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_3' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['allow_url_1:artifact:*.cef.fromEmail', 'allow_url_1:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'send_email_3' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'body': "The URL has been unblocked for 24 hours",
                'to': inputs_item_1[0],
                'from': "security@phantom.us",
                'attachments': "",
                'subject': "Unblock Request Accepted",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act("send email", parameters=parameters, assets=['smtp'], callback=join_set_status_4, name="send_email_3", parent_action=action)

    return

def set_status_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_status_4() called')

    phantom.set_status(container, "closed")

    return

def join_set_status_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_set_status_4() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_set_status_4_called'):
        return

    # no callbacks to check, call connected block "set_status_4"
    phantom.save_run_data(key='join_set_status_4_called', value='set_status_4', auto=True)

    set_status_4(container=container, handle=handle)
    
    return

def disallow_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('disallow_url_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'disallow_url_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['allow_url_1:action_result.parameter.url', 'allow_url_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'disallow_url_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })
    # calculate start time using delay of 1 minutes
    start_time = datetime.now() + timedelta(minutes=1)

    phantom.act("disallow url", parameters=parameters, assets=['blue_coat'], start_time=start_time, name="disallow_url_1", parent_action=action)

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