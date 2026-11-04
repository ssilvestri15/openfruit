#pragma once

#include <optional>
#include <string_view>

namespace openib {

// Returns the measured text height in points when a suitable host font and
// layout backend are available. This does not change the archived UIFont.
std::optional<double> measure_text_height(std::string_view text,
                                          std::string_view font_name,
                                          double point_size,
                                          double container_width,
                                          bool system_font);

} // namespace openib
