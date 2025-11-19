from fuzzingbook.GUIFuzzer import GUICoverageFuzzer, GUIRunner

from selenium.common.exceptions import ElementClickInterceptedException, ElementNotInteractableException, NoSuchElementException

from typing import Tuple


class JuicyFuzzer(GUICoverageFuzzer):
    def run(self, runner: GUIRunner) -> Tuple[str, str]:  # type: ignore
        """Run the fuzzer on the given GUIRunner `runner`."""
        assert isinstance(runner, GUIRunner)

        self.restart()
        action = self.fuzz()
        self.state_symbol = self.fsm_last_state_symbol(self.derivation_tree)

        if self.log_gui_exploration:
            print("Action", action.strip(), "->", self.state_symbol)

        result, outcome = runner.run(action)

        if self.state_symbol != self.miner.FINAL_STATE:
            self.update_state()

        return self.state_symbol, outcome
    

    def explore_all(self, runner: GUIRunner, max_actions=100) -> None:
        """Explore all states of the GUI, up to `max_actions` (default 100)."""

        actions = 0
        while (self.miner.UNEXPLORED_STATE in self.grammar and 
               actions < max_actions):
            actions += 1
            if self.log_gui_exploration:
                print("Run #" + repr(actions))
            try:
                symbol, outcome = self.run(runner)
                print(outcome)
            except ElementClickInterceptedException:
                print("ElementClickInterceptedException")
                pass
            except ElementNotInteractableException:
                print("ElementNotInteractableException")
                pass
            except NoSuchElementException:
                print("NoSuchElementException")
                pass
