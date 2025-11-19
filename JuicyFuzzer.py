from fuzzingbook.GUIFuzzer import GUICoverageFuzzer, GUIRunner

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