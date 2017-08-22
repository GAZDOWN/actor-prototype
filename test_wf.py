#!/usr/bin/python

import yaml
import os
from pprint import pprint
import logging
import snactor.executors
from snactor.loader import load
from snactor.registry import get_actor

WF_PATH = "workflow"
WF_ACTORS_DEF = "workflow.yaml"

def build_path(path_members):
    path = ""

    for member in path_members:
        path = os.path.join(path, member)

    return path

def execute_tasks(tasks, data):
    for task in tasks:
        if isinstance(task, dict):
            for item in task.values():
                execute_tasks(item, data)
            continue 

        if not get_actor(task)().execute(data):
            raise Exception("TEST EXCEPTION")
        pprint(task)
        pprint(data)

    return data


if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
    
    # initial data for "static" composer
    in_data = {
        "shallow": {"value": "True"},
        "source_host": "127.0.0.1",
        "target_host": "127.0.0.1"
    }
    
    workflows = yaml.load(open(WF_ACTORS_DEF))
    for workflow in workflows["workflows"]:
        wf_name = workflow["name"]
    
        load(build_path(["workflow", wf_name]))

        execute_tasks(workflow.get("tasks"), in_data)
    
    
    #data = {}
    #print get_actor('osversion')().execute(data)
    #pprint(data)
