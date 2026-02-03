#ifndef MESHCHAIN_TOKEN_BUCKET_QOS_H
#define MESHCHAIN_TOKEN_BUCKET_QOS_H

#include <map>
#include <chrono>
#include <string>
#include <cmath>
#include "../common/types.h"

namespace meshchain {
namespace network {

/**
 * Reputation-Weighted Token Bucket QoS (Paper Algorithm 6)
 *
 * Implements rate limiting based on reputation score:
 * - Rate: base * R^2 (quadratic scaling)
 * - Burst: 5 * rate
 * - Cost: Message type dependent (BLOCK:5, WITNESS_REQ:2, else:1)
 *
 * From paper Section 5.6:
 * admit ⇐⇒ tokens_s >= cost
 * tokens_s <- min{C_s, tokens_s - cost + rate * Δt}
 */

enum class MessageType {
    BLOCK = 5,
    WITNESS_REQ = 2,
    ANCHOR = 3,
    DATA_REQUEST = 2,
    OTHER = 1
};

struct TokenBucket {
    double tokens;           // Current token count
    double capacity;         // Maximum (burst) capacity
    double refill_rate;      // Tokens per second
    Timestamp last_update;   // Last refill timestamp

    TokenBucket() : tokens(0), capacity(0), refill_rate(0) {
        last_update = std::chrono::system_clock::now();
    }

    TokenBucket(double rate) : capacity(5.0 * rate), refill_rate(rate) {
        tokens = capacity;  // Start full
        last_update = std::chrono::system_clock::now();
    }

    // Refill tokens based on elapsed time
    void refill() {
        auto now = std::chrono::system_clock::now();
        auto elapsed = std::chrono::duration<double>(now - last_update).count();

        tokens = std::min(capacity, tokens + refill_rate * elapsed);
        last_update = now;
    }

    // Try to consume tokens
    bool tryConsume(double cost) {
        refill();
        if (tokens >= cost) {
            tokens -= cost;
            return true;
        }
        return false;
    }

    // Get fill percentage
    double fillPercentage() const {
        return (capacity > 0) ? (tokens / capacity) : 0.0;
    }
};

class TokenBucketQoS {
public:
    struct Config {
        double base_rate;
        double learning_rate;
        bool enable_penalties;
        double penalty_amount;

        Config() : base_rate(10.0), learning_rate(0.01),
                   enable_penalties(true), penalty_amount(0.01) {}
    };

    TokenBucketQoS() : config_() {}

    explicit TokenBucketQoS(const Config& config)
        : config_(config) {}

    /**
     * Enforce QoS (Paper Algorithm 6)
     *
     * INPUT: message, sender reputation
     * OUTPUT: {Accept, Drop} + optional priority
     *
     * Pseudocode from paper:
     *   r ← GetRep(sender); r ∈ [0,1]
     *   rate := base * r^2; burst := 5 * rate
     *   tokens := min(burst, tokens + elapsed * rate)
     *   cost := Cost(msg.type)
     *   if tokens < cost:
     *       AdjustRep(sender, -0.01); return Drop
     *   tokens := tokens - cost
     *   return Accept(PriorityFromRep(r))
     */
    struct QoSDecision {
        bool accept;
        double priority;  // Higher reputation = higher priority
        std::string reason;
    };

    QoSDecision enforceQoS(const std::string& sender_id,
                          MessageType msg_type,
                          Reputation& sender_rep) {
        // Step 1: Get reputation score r ∈ [0,1]
        double r = sender_rep.R;

        // Step 2: Ensure sender has a token bucket
        if (buckets_.find(sender_id) == buckets_.end()) {
            double rate = config_.base_rate * r * r;  // Quadratic scaling
            buckets_[sender_id] = TokenBucket(rate);
        }

        TokenBucket& bucket = buckets_[sender_id];

        // Step 3: Update bucket parameters based on current reputation
        double rate = config_.base_rate * r * r;
        bucket.refill_rate = rate;
        bucket.capacity = 5.0 * rate;

        // Step 4: Get message cost
        double cost = static_cast<double>(msg_type);

        // Step 5: Try to consume tokens
        if (!bucket.tryConsume(cost)) {
            // Rate limit exceeded - drop message and penalize
            if (config_.enable_penalties) {
                sender_rep.R = std::max(MIN_REPUTATION,
                                       sender_rep.R - config_.penalty_amount);
            }

            return QoSDecision{
                .accept = false,
                .priority = 0.0,
                .reason = "Rate limit exceeded (tokens=" +
                         std::to_string(bucket.tokens) + " < cost=" +
                         std::to_string(cost) + ")"
            };
        }

        // Step 6: Accept with priority based on reputation
        double priority = priorityFromReputation(r);

        return QoSDecision{
            .accept = true,
            .priority = priority,
            .reason = "Accepted"
        };
    }

    /**
     * Get current token count for sender (for monitoring)
     */
    double getTokens(const std::string& sender_id) {
        if (buckets_.find(sender_id) == buckets_.end()) {
            return 0.0;
        }
        buckets_[sender_id].refill();
        return buckets_[sender_id].tokens;
    }

    /**
     * Get bucket fill percentage
     */
    double getFillPercentage(const std::string& sender_id) {
        if (buckets_.find(sender_id) == buckets_.end()) {
            return 0.0;
        }
        buckets_[sender_id].refill();
        return buckets_[sender_id].fillPercentage();
    }

    /**
     * Reset bucket for sender (useful for testing)
     */
    void resetBucket(const std::string& sender_id) {
        buckets_.erase(sender_id);
    }

    /**
     * Get statistics
     */
    struct Statistics {
        size_t total_buckets;
        double avg_fill_percentage;
        size_t total_requests;
        size_t accepted_requests;
        size_t dropped_requests;
    };

    Statistics getStatistics() const {
        Statistics stats;
        stats.total_buckets = buckets_.size();
        stats.avg_fill_percentage = 0.0;
        stats.total_requests = total_requests_;
        stats.accepted_requests = accepted_requests_;
        stats.dropped_requests = dropped_requests_;

        if (!buckets_.empty()) {
            double total_fill = 0.0;
            for (const auto& [id, bucket] : buckets_) {
                total_fill += bucket.fillPercentage();
            }
            stats.avg_fill_percentage = total_fill / buckets_.size();
        }

        return stats;
    }

private:
    Config config_;
    std::map<std::string, TokenBucket> buckets_;

    // Statistics
    size_t total_requests_ = 0;
    size_t accepted_requests_ = 0;
    size_t dropped_requests_ = 0;

    /**
     * Priority from reputation (higher R = higher priority)
     * Using linear mapping: priority ∈ [0, 1] same as R
     */
    double priorityFromReputation(double r) const {
        return r;  // Could be non-linear if needed
    }
};

} // namespace network
} // namespace meshchain

#endif // MESHCHAIN_TOKEN_BUCKET_QOS_H
