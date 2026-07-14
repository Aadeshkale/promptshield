"""
Policy decides what to do after detection.

Detector says:

"I found an AWS key."

Policy decides:

Redact?
Block?
Warn?

For v0.1 we simply return findings unchanged.
"""


class DefaultPolicy:

    def apply(self, findings):

        return findings