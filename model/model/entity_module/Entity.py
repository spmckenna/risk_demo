import numpy as np

# TODO allow for groups of entities; not sure how to best do that yet.

class Entity:

    def __init__(self, uuid, typ, label="", owner=None):
        self.type = typ
        self.uuid = uuid
        self.value = {}
        self.parents = []
        self.children = []
        self.label = label
        self.owner = owner
        self.properties = dict()
        self.impactI = None  # <-- hack for VISTA model
        self.impactR = None  # <-- hack for VISTA model
        self.accessI = None  # <-- hack for VISTA model
        self.accessR = None  # <-- hack for VISTA model
        self.controls = {'csf': {
            "identify": {
                "value": 0.5,
                "categories": {
                    "assetManagement": {
                        "value": 0.5,
                        "subcategories": {
                            "ID.AM-1": 0.5,
                            "ID.AM-2": 0.5,
                            "ID.AM-3": 0.5,
                            "ID.AM-4": 0.5,
                            "ID.AM-5": 0.5,
                            "ID.AM-6": 0.5
                        }
                    },
                    "businessEnvironment": {
                        "value": 0.5,
                        "subcategories": {
                            "ID.BE-1": 0.5,
                            "ID.BE-2": 0.5,
                            "ID.BE-3": 0.5,
                            "ID.BE-4": 0.5,
                            "ID.BE-5": 0.5
                        }
                    },
                    "governance": {
                        "value": 0.5,
                        "subcategories": {
                            "ID.GV-1": 0.5,
                            "ID.GV-2": 0.5,
                            "ID.GV-3": 0.5,
                            "ID.GV-4": 0.5
                        }
                    },
                    "riskAssessment": {
                        "value": 0.5,
                        "subcategories": {
                            "ID.RA-1": 0.5,
                            "ID.RA-2": 0.5,
                            "ID.RA-3": 0.5,
                            "ID.RA-4": 0.5,
                            "ID.RA-5": 0.5,
                            "ID.RA-6": 0.5
                        }
                    },
                    "riskManagementStrategy": {
                        "value": 0.5,
                        "subcategories": {
                            "ID.RM-1": 0.5,
                            "ID.RM-2": 0.5,
                            "ID.RM-3": 0.5
                        }
                    },
                    "supplyChainRiskManagement": {
                        "value": 0.5,
                        "subcategories": {
                            "ID.SC-1": 0.5,
                            "ID.SC-2": 0.5,
                            "ID.SC-3": 0.5,
                            "ID.SC-4": 0.5,
                            "ID.SC-5": 0.5
                        }
                    }
                }
            },
            "protect": {
                "value": 0.5,
                "categories": {
                    "identityManagementAuthenticationAndAccessControl": {
                        "value": 0.5,
                        "subcategories": {
                            "PR.AC-1": 0.5,
                            "PR.AC-2": 0.5,
                            "PR.AC-3": 0.5,
                            "PR.AC-4": 0.5,
                            "PR.AC-5": 0.5,
                            "PR.AC-6": 0.5,
                            "PR.AC-7": 0.5
                        }
                    },
                    "awarenessAndTraining": {
                        "value": 0.5,
                        "subcategories": {
                            "PR.AT-1": 0.5,
                            "PR.AT-2": 0.5,
                            "PR.AT-3": 0.5,
                            "PR.AT-4": 0.5,
                            "PR.AT-5": 0.5
                        }
                    },
                    "dataSecurity": {
                        "value": 0.5,
                        "subcategories": {
                            "PR.DS-1": 0.5,
                            "PR.DS-2": 0.5,
                            "PR.DS-3": 0.5,
                            "PR.DS-4": 0.5,
                            "PR.DS-5": 0.5,
                            "PR.DS-6": 0.5,
                            "PR.DS-7": 0.5,
                            "PR.DS-8": 0.5
                        }
                    },
                    "informationProtectionProcessesAndProcedures": {
                        "value": 0.5,
                        "subcategories": {
                            "PR.IP-1": 0.5,
                            "PR.IP-2": 0.5,
                            "PR.IP-3": 0.5,
                            "PR.IP-4": 0.5,
                            "PR.IP-5": 0.5,
                            "PR.IP-6": 0.5,
                            "PR.IP-7": 0.5,
                            "PR.IP-8": 0.5,
                            "PR.IP-9": 0.5,
                            "PR.IP-10": 0.5,
                            "PR.IP-11": 0.5,
                            "PR.IP-12": 0.5
                        }
                    },
                    "maintenance": {
                        "value": 0.5,
                        "subcategories": {
                            "PR.MA-1": 0.5,
                            "PR.MA-2": 0.5
                        }
                    },
                    "protectiveTechnology": {
                        "value": 0.5,
                        "subcategories": {
                            "PR.PT-1": 0.5,
                            "PR.PT-2": 0.5,
                            "PR.PT-3": 0.5,
                            "PR.PT-4": 0.5,
                            "PR.PT-5": 0.5
                        }
                    }
                }
            },
            "detect": {
                "value": 0.5,
                "categories": {
                    "anomaliesAndEvents": {
                        "value": 0.5,
                        "subcategories": {
                            "DE.AE-1": 0.5,
                            "DE.AE-2": 0.5,
                            "DE.AE-3": 0.5,
                            "DE.AE-4": 0.5,
                            "DE.AE-5": 0.5
                        }
                    },
                    "securityContinuousMonitoring": {
                        "value": 0.5,
                        "subcategories": {
                            "DE.CM-1": 0.5,
                            "DE.CM-2": 0.5,
                            "DE.CM-3": 0.5,
                            "DE.CM-4": 0.5,
                            "DE.CM-5": 0.5,
                            "DE.CM-6": 0.5,
                            "DE.CM-7": 0.5,
                            "DE.CM-8": 0.5
                        }
                    },
                    "detectionProcesses": {
                        "value": 0.5,
                        "subcategories": {
                            "DE.DP-1": 0.5,
                            "DE.DP-2": 0.5,
                            "DE.DP-3": 0.5,
                            "DE.DP-4": 0.5,
                            "DE.DP-5": 0.5
                        }
                    }
                }
            },
            "respond": {
                "value": 0.5,
                "categories": {
                    "responsePlanning": {
                        "value": 0.5,
                        "subcategories": {
                            "RS.RP-1": 0.5
                        }
                    },
                    "communications": {
                        "value": 0.5,
                        "subcategories": {
                            "RS.CO-1": 0.5,
                            "RS.CO-2": 0.5,
                            "RS.CO-3": 0.5,
                            "RS.CO-4": 0.5,
                            "RS.CO-5": 0.5
                        }
                    },
                    "analysis": {
                        "value": 0.5,
                        "subcategories": {
                            "RS.AN-1": 0.5,
                            "RS.AN-2": 0.5,
                            "RS.AN-3": 0.5,
                            "RS.AN-4": 0.5,
                            "RS.AN-5": 0.5
                        }
                    },
                    "mitigation": {
                        "value": 0.5,
                        "subcategories": {
                            "RS.MI-1": 0.5,
                            "RS.MI-2": 0.5,
                            "RS.MI-3": 0.5
                        }
                    },
                    "improvements": {
                        "value": 0.5,
                        "subcategories": {
                            "RS.IM-1": 0.5,
                            "RS.IM-2": 0.5
                        }
                    }
                }
            },
            "recover": {
                "value": 0.5,
                "categories": {
                    "recoveryPlanning": {
                        "value": 0.5,
                        "subcategories": {
                            "RC.RP-1": 0.5
                        }
                    },
                    "improvements": {
                        "value": 0.5,
                        "subcategories": {
                            "RC.IM-1": 0.5,
                            "RC.IM-2": 0.5
                        }
                    },
                    "communications": {
                        "value": 0.5,
                        "subcategories": {
                            "RC.CO-1": 0.5,
                            "RC.CO-2": 0.5,
                            "RC.CO-3": 0.5
                        }
                    }
                }
            }
        }, 'nist80053': {}}

    def assign_value(self, value, context):
        self.value[context] = value

    # hack for VISTA model:
    def allocate_data_space(self, size):
        self.impactI = np.zeros((size,))
        self.impactR = np.zeros((size,))
        self.accessI = np.zeros((size,))
        self.accessR = np.zeros((size,))


class CriticalEntity(Entity):

    def __init__(self, uuid, label="", owner=None):
        super().__init__(uuid=uuid, typ="critical", label=label, owner=owner)


class Organization(Entity):

    def __init__(self, uuid, label="", owner=None):
        super().__init__(uuid=uuid, typ="organization", label=label, owner=owner)


class Process(Entity):

    def __init__(self, uuid, label="", owner=None):
        super().__init__(uuid=uuid, typ="process", label=label, owner=owner)


class Division(Entity):

    def __init__(self, uuid, label="", owner=None):
        super().__init__(uuid=uuid, typ="division", label=label, owner=owner)


class Application(Entity):

    def __init__(self, uuid, label="", owner=None):
        super().__init__(uuid=uuid, typ="bah", label=label, owner=owner)


class Function(Entity):

    def __init__(self, uuid, label="", owner=None):
        super().__init__(uuid=uuid, typ="function", label=label, owner=owner)


class Asset(Entity):

    def __init__(self, uuid, typ="asset", label="", owner=None):
        super().__init__(uuid=uuid, typ=typ, label=label, owner=owner)
        # hack for VISTA model:
        self.CSF_metrics = {"identify": 0, "protect": 0, "detect": 0, "respond": 0, "recover": 0}


class Server(Asset):

    def __init__(self, uuid, label="", owner=None):
        super().__init__(uuid=uuid, typ="server", label=label, owner=owner)


class Laptop(Asset):

    def __init__(self, uuid, label="", owner=None):
        super().__init__(uuid=uuid, typ="laptop", label=label, owner=owner)


class Desktop(Asset):

    def __init__(self, uuid, label="", owner=None):
        super().__init__(uuid=uuid, typ="desktop", label=label, owner=owner)


class MobileDevice(Asset):

    def __init__(self, uuid, label="", owner=None):
        super().__init__(uuid=uuid, typ="mobile_device", label=label, owner=owner)


class Data(Entity):

    def __init__(self, uuid, label="", owner=None):
        super().__init__(uuid=uuid, typ="data", label=label, owner=owner)


if __name__ == '__main__':
    acme = Entity("organization", "1", label="ACME, Inc.")
    acme.assign_value(100, "self")

    app1 = Application("app1", owner="Jane", label="Payroll")

    svr1 = Server("svr1", owner="Jane", label="Mainframe")
    svr2 = Server("svr2", owner="Steve", label="Print server")
    laptop1 = Laptop("lap1", owner="Hank", label="Employee machine")

    div1 = Entity("div_ops", "div1", label="Operations")
    div2 = Entity("div_all_eps", "div2", label="Employees")

    div1.assign_value(acme.value["self"] * 0.8, "acme")
    div2.assign_value(acme.value["self"] * 0.2, "acme")

    svr1.assign_value(div1.value["acme"] * 0.3, "operations")
    svr2.assign_value(div1.value["acme"] * 0.6, "operations")
    laptop1.assign_value(div2.value["acme"], "all_endpoints")
