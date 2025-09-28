# Green Team Agent Implementations

This document describes the four green team agents implemented for the comprehensive email security demonstration.

## Overview

The green team agents simulate realistic normal user behavior patterns in an enterprise email environment. Each agent has distinct characteristics that reflect their role and responsibilities:

- **Alice Marketing Agent**: Marketing manager with external outreach focus
- **Bob Developer Agent**: Software developer with technical communication patterns  
- **Charlie Assistant Agent**: Executive assistant with administrative coordination
- **Remote User Agent**: Remote worker with occasional access and security risks

## Agent Implementations

### 1. Alice Marketing Agent (`AliceMarketingAgent`)

**Role**: Marketing Manager  
**Node**: `alice_workstation`  
**Email**: `alice@enterprise.com`

**Behavioral Characteristics**:
- **High send frequency**: 6 ± 2 steps (most active emailer)
- **High send probability**: 0.7 (frequent outreach)
- **Moderate attachment usage**: 0.4 probability (marketing materials)
- **Mixed recipients**: 60% internal, 40% external communications

**Email Content**:
- Marketing-focused subjects (newsletters, campaigns, partnerships)
- Professional marketing templates
- Attachment types: newsletters, brochures, reports, event materials

**Use Cases**:
- Demonstrates high-volume legitimate email traffic
- Shows external communication patterns that could be mimicked by attackers
- Tests email filtering with marketing content

### 2. Bob Developer Agent (`BobDeveloperAgent`)

**Role**: Software Developer  
**Node**: `bob_workstation`  
**Email**: `bob@enterprise.com`

**Behavioral Characteristics**:
- **Moderate send frequency**: 10 ± 4 steps (focused communication)
- **Balanced probabilities**: 0.5 send, 0.4 retrieve (collaborative workflow)
- **High attachment usage**: 0.6 probability (technical documents)
- **Internal focus**: 85% internal, 15% external communications

**Email Content**:
- Technical subjects (code reviews, bug reports, documentation)
- Developer-focused templates with technical language
- Attachment types: code files, specifications, test results, diagrams

**Use Cases**:
- Represents technical communication patterns
- Tests attachment scanning with code files
- Shows collaborative development workflows

### 3. Charlie Assistant Agent (`CharlieAssistantAgent`)

**Role**: Executive Assistant  
**Node**: `charlie_workstation`  
**Email**: `charlie@enterprise.com`

**Behavioral Characteristics**:
- **Regular send frequency**: 7 ± 3 steps (administrative tasks)
- **Administrative focus**: 0.6 send probability
- **Multi-recipient emails**: 0.4 probability (company-wide communications)
- **Moderate attachment usage**: 0.5 probability (administrative documents)

**Email Content**:
- Administrative subjects (meetings, policies, schedules)
- Professional administrative templates
- Attachment types: agendas, policies, schedules, reports

**Use Cases**:
- Demonstrates multi-recipient email patterns
- Shows administrative communication workflows
- Tests policy distribution and company-wide announcements

### 4. Remote User Agent (`RemoteUserAgent`)

**Role**: Remote Worker  
**Node**: `remote_workstation`  
**Email**: `remote@enterprise.com`

**Behavioral Characteristics**:
- **Low send frequency**: 15 ± 8 steps (least active)
- **High retrieve probability**: 0.5 (catching up on messages)
- **Low attachment usage**: 0.2 probability (limited resources)
- **Risky behavior**: 0.1 probability (security vulnerability simulation)

**Email Content**:
- Remote work subjects (status updates, connectivity issues, access requests)
- Field worker templates with urgency indicators
- Risky templates (public WiFi, personal devices, security bypasses)
- Attachment types: field reports, logs, photos

**Use Cases**:
- Simulates security risks from remote access
- Tests detection of risky email behavior
- Demonstrates irregular access patterns

## Configuration

### YAML Configuration Structure

```yaml
game:
  agents:
    alice_marketing:
      type: "alice-marketing-agent"
      ref: "alice_marketing"
      agent_settings:
        node_name: "alice_workstation"
        sender_email: "alice@enterprise.com"
        send_probability: 0.7
        attachment_probability: 0.4
        internal_recipients: [...]
        external_recipients: [...]
```

### Key Configuration Parameters

| Parameter | Alice | Bob | Charlie | Remote | Description |
|-----------|-------|-----|---------|--------|-------------|
| `email_frequency` | 6 | 10 | 7 | 15 | Steps between actions |
| `send_probability` | 0.7 | 0.5 | 0.6 | 0.3 | Likelihood of sending |
| `attachment_probability` | 0.4 | 0.6 | 0.5 | 0.2 | Attachment inclusion |
| `email_variance` | 2 | 4 | 3 | 8 | Timing randomness |

## Testing

### Unit Tests (`test_green_team_agents.py`)
- Agent initialization and configuration validation
- Content generation (subjects, bodies, attachments)
- Recipient selection logic
- Action generation and request formatting
- Behavioral probability testing

### Integration Tests (`test_green_team_agent_integration.py`)
- Configuration file validation
- Agent creation from YAML configuration
- Network topology integration
- Behavioral differentiation verification

## Usage Examples

### Creating Agents from Configuration

```python
from primaite_mail.game.agents import AliceMarketingAgent

# Load from configuration
config = {
    "ref": "alice_marketing",
    "team": "GREEN",
    "type": "alice-marketing-agent",
    "agent_settings": {
        "node_name": "alice_workstation",
        "sender_email": "alice@enterprise.com"
    }
}

alice = AliceMarketingAgent.from_config(config)
```

### Getting Agent Actions

```python
# Get action based on current timestep
action_name, parameters = alice.get_action(timestep=50)

# Example output:
# ("email-send", {
#     "node_name": "alice_workstation",
#     "to": ["partner@client.com"],
#     "subject": "Monthly Newsletter - Company Updates",
#     "body": "Dear Team,\n\nPlease find attached...",
#     "sender": "alice@enterprise.com",
#     "attachments": ["newsletter.pdf"]
# })
```

### Request Formatting

```python
# Format action into simulation request
request = alice.format_request(action_name, parameters)

# Example output:
# ["network", "node", "alice_workstation", "application", 
#  "email-client", "send_email", {...parameters}]
```

## Security Considerations

### Realistic Attack Vectors
- **Alice**: External communications could be spoofed by attackers
- **Bob**: Technical attachments could contain malware
- **Charlie**: Multi-recipient emails could spread threats quickly
- **Remote**: Risky behaviors create security vulnerabilities

### Detection Opportunities
- **Volume Analysis**: Alice's high email volume vs. others
- **Attachment Scanning**: Bob's frequent technical attachments
- **Distribution Patterns**: Charlie's multi-recipient emails
- **Risk Indicators**: Remote user's risky behavior flags

## Future Enhancements

1. **Dynamic Behavior**: Agents could adapt based on security events
2. **Seasonal Patterns**: Marketing campaigns, development cycles
3. **Collaboration Networks**: Inter-agent communication patterns
4. **Learning Capabilities**: Agents learn from defensive responses
5. **Role Expansion**: Additional user types (HR, Finance, etc.)

## Files Created

- `src/primaite_mail/game/agents/alice_marketing_agent.py`
- `src/primaite_mail/game/agents/bob_developer_agent.py`
- `src/primaite_mail/game/agents/charlie_assistant_agent.py`
- `src/primaite_mail/game/agents/remote_user_agent.py`
- `tests/assets/configs/green_team_agents_config.yaml`
- `tests/unit_tests/test_green_team_agents.py`
- `tests/integration_tests/test_green_team_agent_integration.py`

All agents follow PrimAITE development patterns and integrate seamlessly with the existing email security simulation framework.