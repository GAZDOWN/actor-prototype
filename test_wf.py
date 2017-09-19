#!/usr/bin/python

import yaml
import os
from pprint import pprint
import logging
import snactor.executors
from snactor.loader import load, load_schemas, validate_actor_types
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
            # take first value and iterrate over it
            execute_tasks(task.itervalues().next(), data)
            continue 

        if not get_actor(task).execute(data):
            raise RuntimeError("Actor {} returned non-zero value".format(task))

    return data


if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
    
    workflows = yaml.load(open(WF_ACTORS_DEF))
    for workflow in workflows["workflows"]:
        wf_name = workflow.get("name")
        in_data = workflow.get("init", {})
        print("{} initial data: ".format(wf_name))
        pprint(in_data)
        print("======================================================")

        #for task in workflow.get("tasks"):
        #    load_schemas(build_path(["workflow", wf_name, task, "schema"]))
        #    
        #load_schemas(build_path(["workflow", wf_name, "portscan", "schema"]))

        load(build_path(["workflow", wf_name]))
        validate_actor_types()
        execute_tasks(workflow.get("tasks"), in_data)

        print("======================================================")
        print("Result of workflow {}:".format(wf_name))
        pprint(in_data)
        print("======================================================")
