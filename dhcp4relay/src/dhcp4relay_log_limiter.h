#pragma once

#include <chrono>
#include <cstdint>

struct RateLimitedLogResult {
    bool should_log;
    uint64_t suppressed_packet_count;
};

/*
 * Tracks repeated log events for one relay VLAN. The first event is reported
 * immediately; later events are counted until the reporting interval expires.
 */
class PerVlanLogRateLimiter {
public:
    using Clock = std::chrono::steady_clock;

    explicit PerVlanLogRateLimiter(std::chrono::seconds interval = std::chrono::seconds(60))
        : interval_(interval) {}

    RateLimitedLogResult record(Clock::time_point now) {
        if (!has_reported_) {
            has_reported_ = true;
            last_report_time_ = now;
            return {true, 0};
        }

        ++suppressed_packet_count_;
        if (now - last_report_time_ < interval_) {
            return {false, 0};
        }

        const auto suppressed = suppressed_packet_count_;
        suppressed_packet_count_ = 0;
        last_report_time_ = now;
        return {true, suppressed};
    }

    void reset() {
        has_reported_ = false;
        last_report_time_ = Clock::time_point{};
        suppressed_packet_count_ = 0;
    }

    uint64_t suppressed_packet_count() const {
        return suppressed_packet_count_;
    }

private:
    std::chrono::seconds interval_;
    Clock::time_point last_report_time_{};
    uint64_t suppressed_packet_count_ = 0;
    bool has_reported_ = false;
};
