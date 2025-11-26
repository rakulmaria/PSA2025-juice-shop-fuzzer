from fuzzingbook.GUIFuzzer import GUICoverageFuzzer, GUIRunner
from selenium.webdriver.support.ui import WebDriverWait

from typing import Tuple


class JuicyFuzzer(GUICoverageFuzzer):
    def restart(self) -> None:
        self.driver.get(self.initial_url)
        self.state = frozenset(self.miner.START_STATE)
        WebDriverWait(self.driver, 5, 1).until(lambda x: "login" in self.driver.current_url)

    def run(self, runner: GUIRunner) -> Tuple[str, str]:  # type: ignore
        """Run the fuzzer on the given GUIRunner `runner`."""
        assert isinstance(runner, GUIRunner)

        self.restart()
        action = self.fuzz()
        self.state_symbol = self.fsm_last_state_symbol(self.derivation_tree)

        if self.log_gui_exploration:
            print("Action", action.strip(), "->", self.state_symbol)

        error_msg, result = runner.run(action)

        if self.state_symbol != self.miner.FINAL_STATE:
            self.update_state()

        return error_msg, result


    def explore_all(self, runner: GUIRunner, max_actions=100) -> None:
        """Explore all states of the GUI, up to `max_actions` (default 100)."""

        actions = 0
        while (self.miner.UNEXPLORED_STATE in self.grammar and 
               actions < max_actions):
            actions += 1
            if self.log_gui_exploration:
                print("Run #" + repr(actions))
            
            error_msg, result = self.run(runner)

            if self.log_gui_exploration:
                if result != runner.PASS:
                    print(f"Found error during explore: {error_msg}")