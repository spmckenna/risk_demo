import numpy as np


# hacked, dumbed-down version for single node VISTA model

def from_node_to_node(graph, from_node, objective_node, attack_type, all_assets_list, failed_node_list):
    attack_graph = graph

    # Find all paths from the from_node to each to_node
    all_paths = find_all_paths(attack_graph, from_node, objective_node)

    all_paths = [ap for ap in all_paths if len(ap) > 0]
    if len(all_paths) == 0:
        return None

    ct = 0
    end_point = None
    while ct < 3:  # TODO make 3 equal len all paths?
        p_ = np.random.choice(np.arange(0, len(all_paths)))
        p = all_paths[p_]
        path = [n for n in p if n != 'hub']
        if len(path) == 1:
            node = path[0]
        else:
            node = path[1]

        choose_from = list(set(all_assets_list) - set(failed_node_list))
        if len(choose_from) > 0:
            end_point = [i for i in choose_from if i.uuid == node][0]
            break
        else:
            ct += 1

    return end_point


def find_all_paths(graph, start, end):
    path = []
    paths = []
    queue = [(start, end, path)]
    while queue:
        start, end, path = queue.pop()

        path = path + [start]
        if start == end:
            paths.append(path)
        for node in set(graph[start]).difference(path):
            queue.append((node, end, path))

    return paths
