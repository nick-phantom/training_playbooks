"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'geolocate_ip_1' block
    geolocate_ip_1(container=container)

    # call 'set_severity_4' block
    set_severity_4(container=container)

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_ip_1() called')

    # collect data for 'geolocate_ip_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])
    
    phantom.debug(container_data)
    
    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], callback=decision_1, name="geolocate_ip_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["geolocate_ip_1:action_result.data.*.country_iso_code", "==", "US"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ip_reputation_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['geolocate_ip_1:action_result.parameter.ip', 'geolocate_ip_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("ip reputation", parameters=parameters, assets=['virustotal'], callback=decision_2, name="ip_reputation_1")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["ip_reputation_1:action_result.summary.detected_urls", ">", "5"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        promote_to_case_1(action=action, success=success, container=container, results=results, handle=handle)
        pin_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def promote_to_case_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('promote_to_case_1() called')

    phantom.promote(container=container, template="Response Template 1")

    return

def pin_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('pin_2() called')

    results_data_1 = phantom.collect2(container=container, datapath=['ip_reputation_1:action_result.summary.detected_urls'], action_results=results)

    results_item_1_0 = [item[0] for item in results_data_1]

    phantom.pin(container=container, data=results_item_1_0, message="malicious urls", pin_type="card", pin_style="red", name="malicious urls")

    return

def set_severity_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_severity_4() called')

    phantom.set_severity(container=container, severity="Critical")
    set_status_5(container=container)

    return

def set_status_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_status_5() called')

    phantom.set_status(container=container, status="Test")

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions
    # can be collected here.
    
    lat_long = phantom.collect2(container=container, datapath=['geolocate_ip_1:action_result.data.*.latitude', 'geolocate_ip_1:action_result.data.*.longitude'])
    malicious_urls = phantom.collect2(container=container, datapath=['ip_reputation_1:action_result.data.*.detected_urls.*.url'])
    
    phantom.error("=== LAT/LONG ===")
    phantom.debug(lat_long)
    
    phantom.error("=== MALICIOUS URLS ===")
    for i in malicious_urls:
        phantom.debug(i)
    
    summary_json = phantom.get_summary()
    if 'result' in summary_json:
        for action_result in summary_json['result']:
            if 'action_run_id' in action_result:
                action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                phantom.debug(action_results)

    return