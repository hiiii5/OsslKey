#ifndef OSSL_RESULT_H
#define OSSL_RESULT_H
#pragma once

#include <memory>
#include <string>

namespace ossl {
class OsslResult final {
  /**
   * @brief Convert a string to a C-style string
   *
   * @tparam T The type of the string
   * @param t The string to convert
   * @return const char* The C-style string
   */
  template <typename T> static auto Convert(T &&t) {
    if constexpr (std::is_same_v<std::remove_cv_t<std::remove_reference_t<T>>,
                                 std::string>) {
      return std::forward<T>(t).c_str();
    } else {
      return std::forward<T>(t);
    }
  }

  /**
   * @brief Format a string
   *
   * @tparam Args The types of the arguments
   * @param format The format string
   * @param args The arguments
   * @return std::string The formatted string
   * @warning Does not support non-trivial types
   */
  template <typename... Args>
  static std::string FormatInternal(const std::string &format, Args... args) {
    // Extra space for '\0'
    // We aren't passing non-trivial types, probably, so we should be safe since
    // it will just print the address Also the format string is a non-user
    // defined string so we shouldn't have to worry about format string attacks
    const int sizeS =
        std::snprintf(nullptr, 0, format.c_str(), std::forward<Args>(args)...) +
        1;
    if (sizeS <= 0) {
      return "";
    }

    const size_t size = static_cast<size_t>(sizeS);
    const auto buffer = std::make_unique<char[]>(size);
    auto retSize = std::snprintf(buffer.get(), size, format.c_str(),
                                 std::forward<Args>(args)...);
    return {buffer.get(),
            buffer.get() + size - 1}; // We don't want the '\0' inside
  }

  /**
   * @brief Format a string
   *
   * @tparam Args The types of the arguments
   * @param format The format string
   * @param args The arguments
   * @return std::string The formatted string
   * @note Hacked to support tuples through the convert function
   */
  template <typename... Args>
  static std::string Format(const std::string &format, Args... args) {
    return FormatInternal(format, Convert(std::forward<Args>(args))...);
  }

  static std::string FormatErrorTuple(
      const std::tuple<unsigned long, std::string> &error) noexcept {
    return Format("Error code: %lu, Error message: %s", std::get<0>(error),
                  std::get<1>(error));
  }

public:
  /**
   * @brief The status of the result
   */
  enum class Status { Undefined = -1, Success = 0, Failure = 1 };

  OsslResult() noexcept = default;
  OsslResult(Status status) noexcept : m_status(status) {}
  OsslResult(Status status, const std::string &message) noexcept
      : m_status(status), m_message(message) {}

  /**
   * @brief Construct a new OsslResult object
   *
   * @tparam Args The types of the arguments
   * @param status The status of the result
   * @param format The format string
   * @param args The arguments
   * @example OsslResult{OsslResult::Status::Failure, "Failed to do something
   * with error code: %d", errorCode}
   */
  template <typename... Args>
  OsslResult(Status status, const std::string &format,
             std::tuple<unsigned long, std::string> error) noexcept
      : m_status(status), m_message(Format(format, FormatErrorTuple(error))) {}

  ~OsslResult() noexcept = default;

  OsslResult(const OsslResult &other) noexcept = default;
  OsslResult(OsslResult &&other) noexcept
      : m_status(other.m_status), m_message(std::move(other.m_message)) {}

  OsslResult &operator=(const OsslResult &other) noexcept = default;
  OsslResult &operator=(OsslResult &&other) noexcept {
    m_status = other.m_status;
    m_message = std::move(other.m_message);
    return *this;
  }

  // This allows evaluation as a bool directly instead of an int value.
  explicit operator bool() const noexcept {
    return m_status == Status::Success;
  }

  bool operator==(const OsslResult &other) const noexcept {
    return m_status == other.m_status;
  }

  bool operator!=(const OsslResult &other) const noexcept {
    return m_status != other.m_status;
  }

  [[nodiscard]] const std::string &GetMessage() const noexcept {
    return m_message;
  }

private:
  Status m_status = Status::Undefined;
  std::string m_message;
};
} // namespace ossl

#endif // OSSL_RESULT_H
