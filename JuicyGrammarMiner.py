from fuzzingbook.GUIFuzzer import GUIGrammarMiner
from fuzzingbook.Grammars import START_SYMBOL, Grammar, crange, srange

from selenium.common.exceptions import StaleElementReferenceException
from selenium.webdriver.common.by import By

from typing import Set, FrozenSet

import html


START_STATE = "<state>"
UNEXPLORED_STATE = "<unexplored>"
FINAL_STATE = "<end>"

BETTER_GUI_GRAMMAR: Grammar = ({
        START_SYMBOL: [START_STATE],
        UNEXPLORED_STATE: [""],
        FINAL_STATE: [""],

        "<text>": ["<string>"],
        "<string>": ["<character>", "<string><character>"],
        "<character>": ["<letter>", "<digit>", "<special>"],
        "<letter>": crange('a', 'z') + crange('A', 'Z'),

        "<number>": ["<digits>"],
        "<digits>": ["<digit>", "<digits><digit>"],
        "<digit>": crange('0', '9'),

        "<special>": srange(". !"),

        #TODO: Fix this
        "<email>": ["<string>@<string>"],
        "<letters>": ["<letter>", "<letters><letter>"],

        "<boolean>": ["True", "False"],

        #random password
        "<password>": ["<string>"],

        "<hidden>": ["<string>"],
    })

class JuicyGrammarMiner(GUIGrammarMiner):
    GUI_GRAMMAR = BETTER_GUI_GRAMMAR
    def mine_input_element_actions(self) -> Set[str]:
        """Determine all input actions on the current Web page"""

        actions = set()

        for elem in self.driver.find_elements(By.TAG_NAME, "input"):
            try:
                input_type = elem.get_attribute("type")
                input_name = elem.get_attribute("name")
                if input_name is None:
                    input_name = elem.text

                if input_type in ["checkbox", "radio"]:
                    actions.add("check('%s', <boolean>)" % html.escape(input_name))
                elif input_type in ["text", "number", "email", "password"]:
                    actions.add("fill('%s', '<%s>')" % (html.escape(input_name), html.escape(input_type)))
                elif input_type in ["button", "submit"]:
                    actions.add("submit('%s')" % html.escape(input_name))
                elif input_type in ["hidden"]:
                    pass
                else:
                    actions.add("fill('%s', <%s>)" % (html.escape(input_name), html.escape(input_type)))
            except StaleElementReferenceException:
                pass

        return actions
    
    def mine_state_actions(self) -> FrozenSet[str]:
        """Return a set of all possible actions on the current Web site.
        Can be overloaded in subclasses."""
        return frozenset(self.mine_input_element_actions()
                         | self.mine_button_element_actions()) #TODO links are removed for now
