#pragma once

// The OPENFRUIT release version, shown by `openfruit version`, reported in
// capabilities and sent in HTTP User-Agent headers. A release build receives
// it from its tag (`X.Y.Z`, or `X.Y.Z-dev` for a prerelease) through the
// build's OPENFRUIT_RELEASE_VERSION; other builds use the default below.
#ifndef OPENFRUIT_VERSION
#define OPENFRUIT_VERSION "0.1.0"
#endif
#define OPENFRUIT_WIDEN_LITERAL(text) L##text
#define OPENFRUIT_WIDEN(text) OPENFRUIT_WIDEN_LITERAL(text)
#define OPENFRUIT_VERSION_W OPENFRUIT_WIDEN(OPENFRUIT_VERSION)

// The GitHub repository that publishes OPENFRUIT releases.
#define OPENFRUIT_REPOSITORY "ssilvestri15/openfruit"
#define OPENFRUIT_REPOSITORY_W L"ssilvestri15/openfruit"
