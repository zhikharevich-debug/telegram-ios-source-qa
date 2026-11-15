# Native Telegram iOS source QA

An isolated, public-source-only laboratory for building an unmodified pinned Telegram-iOS release and running it in Apple's iOS Simulator on a free standard GitHub-hosted macOS runner.

This is an upstream **source build**, not the App Store binary or a physical-iPhone acceptance test. No private application source, account/session data, phone numbers, login codes, screenshots of private applications or production credentials belong in this repository, its inputs, logs or artifacts.

Only manual workflow dispatch is enabled. Jobs require this repository to remain public and use the standard `xcode-27` runner, never a paid larger runner. Probe artifacts contain machine/toolchain metadata and a clean Simulator screenshot only.

Upstream candidate: `TelegramMessenger/Telegram-iOS` commit `24638bc69bd083981b178dd1e7f921eebbf7fc46` (release 13.2). Build configuration can disable signing for Simulator; application/authentication/WebView source must remain unchanged.

Sources: [GitHub standard runners](https://docs.github.com/en/actions/reference/runners/github-hosted-runners), [Telegram source](https://github.com/TelegramMessenger/Telegram-iOS), [Telegram test API policy](https://core.telegram.org/api/obtaining_api_id#using-telegram-s-open-source-code).
