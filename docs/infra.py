from diagrams import Diagram
from diagrams.aws.compute import EC2
from diagrams.aws.database import RDS
from diagrams.aws.network import ELB

graph_attr = {
    "fontname": "SF Pro Display",
    "fontsize": "12",
}

node_attr = {
    "fontname": "SF Pro Display",
    "fontsize": "12",
}

edge_attr = {
    "fontname": "SF Pro Display",
    "fontsize": "12",
}

with Diagram(
    "Web Service",
    show=False,
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr
):
    ELB("lb") >> EC2("web") >> RDS("userdb")
