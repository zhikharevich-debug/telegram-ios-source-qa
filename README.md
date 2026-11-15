# Native Telegram iOS source QA

An isolated, public-source-only laboratory for building an unmodified pinned Telegram-iOS release and running it in Apple's iOS Simulator on a free standard GitHub-hosted macOS runner.

This is an upstream **source build**, not the App Store binary or a physical-iPhone acceptance test. No private application source, account/session data, phone numbers, login codes, screenshots of private applications or production credentials belong in this repository, its inputs, logs or artifacts.

Only manual workflow dispatch is enabled. Jobs require this repository to remain public and use the standard `xcode-27` runner, never a paid larger runner. Probe artifacts contain machine/toolchain metadata and a clean Simulator screenshot only.

Upstream candidate: `TelegramMessenger/Telegram-iOS` commit `24638bc69bd083981b178dd1e7f921eebbf7fc46` (release 13.2). Build configuration can disable signing for Simulator; application/authentication/WebView source must remain unchanged.

Sources: [GitHub standard runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [Telegram source](https://github.com/TelegramMessenger/Telegram-iOS), [Telegram test API policy](https://core.telegram.org/api/obtaining_api_id#using-telegram-s-open-source-code).

## Native control laboratory

`native-control.yml` runs on the standard free `macos-26` image. Start with target
`settings` to prove XCUITest and the encrypted control path without account data.
Target `telegram` builds the pinned official release 13.0 source with matching
Xcode 26.6, then exposes the same narrowly scoped UI control. Neither target
automatically logs in, imports sessions, creates portal rights or sends messages.

Before each run, configure `QA_CONTROL_KEY` with a fresh random 32-byte key encoded
as URL-safe base64. Keep the office copy outside Git and never use dispatch inputs,
URLs, screenshots or logs for it. Remove the key after the run. The tiny public
endpoint artifact contains only the temporary hostname, fixed session ID, sequence
handoff and expiry. It grants no control without the key. Requests and responses
use authenticated encryption in addition to HTTPS; replayed or altered messages
are rejected. Raw Appium, tunnel and control logs stay on the disposable runner.

The office controller imports `ControlClient` from `scripts/native_control.py`,
passes the key privately and resumes `initial_sequence` from the last verified
receipt. A transport failure invalidates the client; never retry an uncertain
state-changing command. `call('finish')` closes the control window. The workflow
then stops processes and deletes its own Simulator; a finite timeout and hosted
VM teardown bound failed runs. It never uploads a logged-in Simulator image.

Supported UI operations are source, screenshot, element lookup/click/text/clear,
tap, swipe and window size. Arbitrary Appium sessions, shell execution, file
transfer and external upstream URLs are excluded. Production phone numbers,
fresh login codes and second-factor passwords must travel only through the
encrypted private UI channel. Test DC and production acceptance remain distinct.

Actual execution evidence belongs in individual run receipts. A successful
Simulator boot or `simctl launch` alone does not prove Telegram login, an
administrator screen or an application board.
