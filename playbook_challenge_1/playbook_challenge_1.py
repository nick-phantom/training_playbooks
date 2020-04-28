"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    return

def set_severity_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_1() called')

    phantom.set_severity(container, "high")
    promote_to_case_2(container=container)

    return

def set_severity_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_5() called')

    phantom.set_severity(container, "medium")
    pin_8(container=container)

    return

def set_status_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_status_11() called')

    phantom.set_status(container, "closed")

    return

def set_severity_12(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_12() called')

    phantom.set_severity(container, "high")
    promote_to_case_14(container=container)

    return

def set_severity_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_13() called')

    phantom.set_severity(container, "medium")
    pin_16(container=container)

    return

def set_severity_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_4() called')

    phantom.set_severity(container, "low")
    pin_10(container=container)

    return

def promote_to_case_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('promote_to_case_2() called')

    phantom.promote(container=container, template="NIST 800-61")
    pin_7(container=container)

    return

def set_owner_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_owner_3() called')

    phantom.set_owner(container, "admin")

    return

def join_set_owner_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_set_owner_3() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_set_owner_3_called'):
        return

    # no callbacks to check, call connected block "set_owner_3"
    phantom.save_run_data(key='join_set_owner_3_called', value='set_owner_3', auto=True)

    set_owner_3(container=container, handle=handle)
    
    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.summary.positives", ">", "5"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        set_severity_12(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.summary.positives", ">", 0],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        set_severity_13(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation_1:action_result.summary.positives", "==", 0],
        ])

    # call connected blocks if condition 3 matched
    if matched_artifacts_3 or matched_results_3:
        set_severity_4(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def promote_to_case_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('promote_to_case_14() called')

    phantom.promote(container=container, template="NIST 800-61")
    pin_15(container=container)

    return

def pin_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_8() called')

    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:action_result.summary.positives'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.pin(container=container, message="hash had between 0-5 positives", data=results_item_1_0, pin_type="card_large", pin_style="purple")
    join_set_owner_3(container=container)

    return

def pin_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_16() called')

    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.summary.positives'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.pin(container=container, message="URL had between 0-5 positives", data=results_item_1_0, pin_type="card_large", pin_style="purple")
    join_set_owner_3(container=container)

    return

def pin_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_7() called')

    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:action_result.summary.positives'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.pin(container=container, message="hash had more than 5 positives", data=results_item_1_0, pin_type="card_large", pin_style="red")
    join_set_owner_3(container=container)

    return

def pin_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_15() called')

    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.summary.positives'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.pin(container=container, message="URL had more than 5 positives", data=results_item_1_0, pin_type="card_large", pin_style="red")
    join_set_owner_3(container=container)

    return

def pin_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_10() called')

    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation_1:action_result.summary.positives'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.pin(container=container, message="There were no malicious results", data=results_item_1_0, pin_type="card_large", pin_style="white")
    set_status_11(container=container)

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal'], callback=decision_1, name="file_reputation_1")

    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('url_reputation_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'url_reputation_1' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:artifact:*.cef.requestURL', 'file_reputation_1:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'url': inputs_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act("url reputation", parameters=parameters, assets=['virustotal'], callback=decision_2, name="url_reputation_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">", "5"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        set_severity_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">", 0],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        set_severity_5(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3
    matched_artifacts_3, matched_results_3 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", "==", 0],
        ])

    # call connected blocks if condition 3 matched
    if matched_artifacts_3 or matched_results_3:
        url_reputation_1(action=action, success=success, container=container, results=results, handle=handle)
        return

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