#include "../include/RiskEngine.h"

namespace rollbackguard
{
    namespace
    {
        ThreatAction ResolveAction(double score, const RiskInput& input) noexcept
        {
            std::uint32_t code = input.actionCritical;

            if (score < input.lowThreshold)
            {
                code = input.actionLow;
            }
            else if (score < input.midThreshold)
            {
                code = input.actionMid;
            }
            else if (score < input.highThreshold)
            {
                code = input.actionHigh;
            }
            else if (score < input.criticalThreshold)
            {
                code = input.actionCritical;
            }

            switch (code)
            {
            case 0:
                return ThreatAction::Allow;
            case 7:
                return ThreatAction::Terminate;
            case 2:
            default:
                return ThreatAction::Block;
            }
        }
    }

    RiskOutput EvaluateRisk(const RiskInput& input) noexcept
    {
        const auto total = input.modelScore + input.behaviorScore;
        return RiskOutput
        {
            total,
            ResolveAction(total, input)
        };
    }
}
