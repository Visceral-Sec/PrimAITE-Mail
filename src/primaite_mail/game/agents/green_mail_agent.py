# © Crown-owned copyright 2025, Defence Science and Technology Laboratory UK
"""Green mail agent that sends emails periodically to simulate normal user behavior."""

import random
from typing import Any, Dict, List, Tuple

from gymnasium.core import ObsType
from pydantic import Field, model_validator

from primaite.game.agent.interface import AbstractScriptedAgent
from primaite.interface.request import RequestFormat

__all__ = ("GreenMailAgent",)


class GreenMailAgent(AbstractScriptedAgent, discriminator="green-mail-agent"):
    """
    Green agent that simulates normal email usage patterns using the existing email action system.
    
    This agent uses probabilistic behavior to send emails, retrieve emails, or remain idle,
    representing realistic user email activity patterns in a cybersecurity training environment.
    """

    config: "GreenMailAgent.ConfigSchema" = Field(default_factory=lambda: GreenMailAgent.ConfigSchema())

    class AgentSettingsSchema(AbstractScriptedAgent.AgentSettingsSchema):
        """Schema for the `agent_settings` part of the agent config."""

        send_probability: float = 0.6
        """Probability of sending an email when taking action (default: 0.6)."""
        
        retrieve_probability: float = 0.3
        """Probability of checking emails when taking action (default: 0.3)."""
        
        idle_probability: float = 0.1
        """Probability of doing nothing when taking action (default: 0.1)."""
        
        email_frequency: int = 8
        """Average steps between email actions (default: 8)."""
        
        email_variance: int = 3
        """Random variance in timing (default: 3)."""
        
        node_name: str
        """The name of the node where this agent operates."""
        
        sender_email: str
        """The email address of this agent."""
        
        recipients: List[str] = ["bob@company.com"]
        """List of possible email recipients."""
        
        email_subjects: List[str] = [
            "Daily Report",
            "Meeting Update", 
            "Project Status",
            "Quick Question",
            "Weekly Summary",
            "Document Review",
            "Schedule Confirmation",
            "Follow Up"
        ]
        """List of possible email subjects."""
        
        email_templates: List[str] = [
            "Hi,\n\nHere is today's report as requested.\n\nBest regards",
            "Hello,\n\nPlease review the attached document.\n\nThanks",
            "Hi there,\n\nCan we schedule a meeting for next week?\n\nRegards", 
            "Hello,\n\nHere's the weekly status update.\n\nBest",
            "Hi,\n\nQuick question about the project timeline.\n\nThanks",
            "Hello,\n\nThe meeting is confirmed for tomorrow.\n\nSee you then"
        ]
        """List of email body templates."""

        @model_validator(mode="after")
        def validate_probabilities(self) -> "GreenMailAgent.AgentSettingsSchema":
            """Validate that probabilities are reasonable and variance is less than frequency."""
            # Check that probabilities sum to approximately 1.0 (allow small tolerance)
            total_prob = self.send_probability + self.retrieve_probability + self.idle_probability
            if not (0.9 <= total_prob <= 1.1):
                raise ValueError(
                    f"Probabilities should sum to approximately 1.0, got {total_prob:.2f}"
                )
            
            # Check variance is less than frequency
            if self.email_variance >= self.email_frequency:
                raise ValueError(
                    f"Email variance must be lower than frequency "
                    f"{self.email_variance=}, {self.email_frequency=}"
                )
            
            return self

    class ConfigSchema(AbstractScriptedAgent.ConfigSchema):
        """Configuration Schema for Green Mail Agent."""

        type: str = "green-mail-agent"
        agent_settings: "GreenMailAgent.AgentSettingsSchema" = Field(
            default_factory=lambda: GreenMailAgent.AgentSettingsSchema()
        )

    emails_sent: int = 0
    """Number of emails sent so far."""
    
    emails_retrieved: int = 0
    """Number of times emails were retrieved."""
    
    next_action_timestep: int = 0
    """Timestep when the next action should be taken."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        # Start with a small random delay
        self._set_next_action_timestep(timestep=random.randint(1, 5))

    def _set_next_action_timestep(self, timestep: int) -> None:
        """Set the next action timestep with configured random variance."""
        variance = self.config.agent_settings.email_variance
        frequency = self.config.agent_settings.email_frequency
        random_increment = random.randint(-variance, variance)
        self.next_action_timestep = max(timestep + 1, timestep + frequency + random_increment)

    def _should_take_action(self, timestep: int) -> bool:
        """Determine if it's time to take an action based on timing logic."""
        return timestep >= self.next_action_timestep

    def _generate_email_content(self) -> Tuple[str, str]:
        """Generate random email subject and body."""
        subject = random.choice(self.config.agent_settings.email_subjects)
        body = random.choice(self.config.agent_settings.email_templates)
        return subject, body

    def _select_recipients(self) -> List[str]:
        """Select random recipients from the available list."""
        if not self.config.agent_settings.recipients:
            return []
        
        # Select 1-2 recipients randomly
        num_recipients = random.randint(1, min(2, len(self.config.agent_settings.recipients)))
        return random.sample(self.config.agent_settings.recipients, num_recipients)

    def _get_email_action(self) -> Tuple[str, Dict]:
        """Select appropriate email action from action space using probabilities."""
        # Normalize probabilities
        send_prob = self.config.agent_settings.send_probability
        retrieve_prob = self.config.agent_settings.retrieve_probability
        idle_prob = self.config.agent_settings.idle_probability
        
        total_prob = send_prob + retrieve_prob + idle_prob
        send_prob /= total_prob
        retrieve_prob /= total_prob
        idle_prob /= total_prob
        
        # Generate random number and select action
        rand = random.random()
        
        if rand < send_prob:
            # Send email action
            subject, body = self._generate_email_content()
            recipients = self._select_recipients()
            
            if not recipients:
                return "do-nothing", {}
            
            self.emails_sent += 1
            return "email-send", {
                "node_name": self.config.agent_settings.node_name,
                "to": recipients,
                "subject": subject,
                "body": body,
                "sender": self.config.agent_settings.sender_email
            }
            
        elif rand < send_prob + retrieve_prob:
            # Retrieve emails action
            self.emails_retrieved += 1
            return "email-retrieve", {
                "node_name": self.config.agent_settings.node_name,
                "username": self.config.agent_settings.sender_email
            }
        
        else:
            # Do nothing (idle)
            return "do-nothing", {}

    def get_action(self, obs: ObsType = None, timestep: int = 0) -> Tuple[str, Dict]:
        """
        Main decision logic for selecting actions based on probabilistic email behavior.
        
        Uses timing logic to determine when to act, then probabilistically selects
        between sending emails, retrieving emails, or doing nothing.
        
        :param obs: Current observation (not used in this scripted agent)
        :param timestep: Current simulation timestep
        :return: Action tuple in (action_name, parameters) format
        """
        # Check if it's time to take an action
        if not self._should_take_action(timestep):
            return "do-nothing", {}
        
        # Schedule next action
        self._set_next_action_timestep(timestep)
        
        # Select and return email action based on probabilities
        return self._get_email_action()

    def format_request(self, action: str, options: Dict[str, Any]) -> RequestFormat:
        """
        Format email actions into requests that the simulation can process.
        
        This method translates the green mail agent's actions into proper simulation requests.
        """
        if action == "email-send":
            # Convert email-send action to email client request
            return [
                "network",
                "node", 
                options["node_name"],
                "application",
                "email-client",
                "send_email",
                {
                    "to": options["to"],
                    "subject": options["subject"],
                    "body": options["body"],
                    "from": options["sender"]
                }
            ]
        elif action == "email-retrieve":
            # Convert email-retrieve action to email client request
            return [
                "network",
                "node",
                options["node_name"],
                "application", 
                "email-client",
                "retrieve_emails",
                {
                    "username": options["username"],
                    "password": options.get("password", "")
                }
            ]
        elif action == "do-nothing":
            # Do nothing action
            return ["do-nothing"]
        else:
            # Fallback to parent implementation for unknown actions
            return super().format_request(action, options)

    def show_status(self) -> None:
        """Display the current status of the green mail agent."""
        from prettytable import PrettyTable
        
        table = PrettyTable(["Property", "Value"])
        table.align = "l"
        table.title = f"Green Mail Agent Status: {self.config.ref}"
        
        table.add_row(["Agent Type", "Green Mail Agent"])
        table.add_row(["Node Name", self.config.agent_settings.node_name])
        table.add_row(["Sender Email", self.config.agent_settings.sender_email])
        table.add_row(["Emails Sent", self.emails_sent])
        table.add_row(["Emails Retrieved", self.emails_retrieved])
        table.add_row(["Next Action Step", self.next_action_timestep])
        table.add_row(["Recipients", ", ".join(self.config.agent_settings.recipients)])
        table.add_row(["Send Probability", f"{self.config.agent_settings.send_probability:.1f}"])
        table.add_row(["Retrieve Probability", f"{self.config.agent_settings.retrieve_probability:.1f}"])
        table.add_row(["Idle Probability", f"{self.config.agent_settings.idle_probability:.1f}"])
        table.add_row(["Email Frequency", f"{self.config.agent_settings.email_frequency} ± {self.config.agent_settings.email_variance}"])
        
        print(table)