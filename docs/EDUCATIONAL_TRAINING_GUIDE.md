# Educational Materials and Development Training Guide

## Table of Contents
1. [Cybersecurity Learning Objectives](#cybersecurity-learning-objectives)
2. [Instructor Guide](#instructor-guide)
3. [Assessment Rubrics](#assessment-rubrics)
4. [Student Exercises](#student-exercises)
5. [Common Pitfalls and Solutions](#common-pitfalls-and-solutions)
6. [PrimAITE-Mail Development Training](#primaite-mail-development-training)
7. [Troubleshooting and Debugging](#troubleshooting-and-debugging)

## Cybersecurity Learning Objectives

### Primary Learning Goals

The Comprehensive Email Security Demonstration is designed to teach both cybersecurity concepts and practical PrimAITE development skills through hands-on experience with realistic email security scenarios.

#### Cybersecurity Concepts

**1. Email-Based Attack Vectors**
- **Phishing Attacks**: Understanding social engineering techniques, target selection, and email spoofing
- **Malicious Attachments**: Learning about malware delivery, file type exploitation, and attachment-based compromise
- **Business Email Compromise (BEC)**: Studying financial fraud, executive impersonation, and vendor fraud schemes
- **Command and Control (C2)**: Analyzing post-compromise communication, data exfiltration, and persistence mechanisms
- **Email Reconnaissance**: Understanding information gathering, target profiling, and attack preparation

**2. Email Security Defenses**
- **Email Filtering**: Implementing sender blocking, domain blocking, and IP-based restrictions
- **Content Analysis**: Deploying spam detection, phishing identification, and keyword filtering
- **Attachment Security**: Configuring file type restrictions, size limits, and malware scanning
- **Security Policies**: Creating and managing comprehensive email security configurations
- **Incident Response**: Practicing detection, containment, eradication, and recovery procedures

**3. Multi-Agent Security Operations**
- **Red Team Operations**: Simulating sophisticated attack campaigns and adaptive adversary behavior
- **Blue Team Defense**: Implementing proactive monitoring, threat detection, and response coordination
- **Green Team Simulation**: Modeling realistic user behavior patterns and security awareness levels
- **Security Metrics**: Measuring defense effectiveness, false positive rates, and operational impact
- **Policy Optimization**: Analyzing security configurations and improving defensive postures

#### PrimAITE Development Skills

**1. Simulation Architecture**
- **Tree Structure Navigation**: Understanding Simulation → Network → Node → Service/Application hierarchy
- **Request System Mastery**: Implementing proper tree navigation and parameter passing patterns
- **Component Integration**: Connecting services, applications, and agents within the simulation framework
- **Configuration Management**: Using YAML configurations with pydantic validation for reliable setup
- **Error Handling**: Implementing robust error handling and graceful failure recovery

**2. Agent Development**
- **Behavioral Modeling**: Creating realistic agent behavior patterns and decision-making algorithms
- **Action Space Design**: Defining appropriate action spaces for different agent types and roles
- **Multi-Agent Coordination**: Implementing agent interactions and communication patterns
- **Adaptive Behavior**: Developing agents that learn and adapt based on environmental feedback
- **Performance Optimization**: Creating efficient agent implementations for large-scale simulations

**3. Testing and Quality Assurance**
- **Three-Tier Testing**: Implementing unit, integration, and end-to-end testing strategies
- **Output Capture**: Using proper testing patterns to capture and analyze simulation results
- **Code Quality**: Following PEP 8, black formatting, and type hint best practices
- **Debugging Techniques**: Mastering PrimAITE-specific debugging and troubleshooting methods
- **Continuous Integration**: Setting up automated testing and quality assurance workflows

### Learning Progression

#### Beginner Level (Weeks 1-2)
**Cybersecurity Focus:**
- Basic email security concepts
- Simple phishing identification
- Understanding email headers and routing
- Basic security policy configuration

**PrimAITE Focus:**
- Environment setup and activation
- Basic request system usage
- Simple agent configuration
- Running existing demonstrations

**Practical Exercises:**
- Set up PrimAITE-Mail environment
- Execute baseline operations scenario
- Modify basic security policies
- Analyze email traffic patterns

#### Intermediate Level (Weeks 3-4)
**Cybersecurity Focus:**
- Advanced phishing techniques
- Malicious attachment analysis
- Multi-stage attack campaigns
- Defensive response procedures

**PrimAITE Focus:**
- Custom agent development
- Complex request system patterns
- Configuration file creation
- Basic testing implementation

**Practical Exercises:**
- Create custom green team agent
- Implement simple red team attacks
- Design security policy variations
- Develop unit tests for components

#### Advanced Level (Weeks 5-6)
**Cybersecurity Focus:**
- Advanced persistent threats
- Business email compromise
- Comprehensive incident response
- Security metrics and analysis

**PrimAITE Focus:**
- Multi-agent scenario development
- Advanced testing strategies
- Performance optimization
- Integration with external tools

**Practical Exercises:**
- Build complete attack scenarios
- Implement blue team responses
- Create comprehensive test suites
- Develop custom visualization tools

## Instructor Guide

### Course Structure and Delivery

#### Pre-Course Preparation

**Technical Requirements:**
```bash
# Verify student environment setup
pyenv activate primaite
python -c "from primaite.simulator.sim_container import Simulation; print('✅ Ready')"
python -c "from primaite_mail.simulator.smtp_server import SMTPServer; print('✅ Ready')"

# Test notebook execution
jupyter lab --version
# Should show: 3.6.1 or compatible
```

**Required Materials:**
- PrimAITE-Mail installation with all dependencies
- Jupyter Lab environment with ipywidgets
- Access to comprehensive demo notebook
- Testing infrastructure with output capture capability
- Example configuration files and templates

#### Session 1: Introduction and Environment Setup (2 hours)

**Learning Objectives:**
- Understand PrimAITE-Mail purpose and capabilities
- Successfully set up development environment
- Execute first demonstration scenario
- Understand basic cybersecurity concepts

**Instructor Activities:**
1. **Introduction Presentation (30 minutes)**
   - PrimAITE-Mail overview and philosophy
   - Real-world email security challenges
   - Demonstration of complete attack scenario
   - Learning objectives and course structure

2. **Environment Setup Workshop (45 minutes)**
   ```bash
   # Guide students through setup process
   pyenv activate primaite
   pip install -e .[dev]
   jupyter lab
   # Open Comprehensive-Email-Security-Demo.ipynb
   ```

3. **First Scenario Execution (30 minutes)**
   - Execute baseline operations scenario
   - Explain email traffic patterns
   - Discuss normal user behaviors
   - Analyze metrics and visualizations

4. **Q&A and Troubleshooting (15 minutes)**
   - Address setup issues
   - Clarify concepts
   - Preview next session

**Student Deliverables:**
- Working PrimAITE-Mail environment
- Successfully executed baseline scenario
- Screenshot of metrics dashboard
- Written reflection on email security challenges

#### Session 2: Phishing Attacks and Detection (2 hours)

**Learning Objectives:**
- Understand phishing attack methodologies
- Implement basic email security policies
- Analyze attack success and failure patterns
- Practice incident identification procedures

**Instructor Activities:**
1. **Phishing Attack Analysis (45 minutes)**
   - Execute phishing campaign scenario
   - Analyze social engineering techniques
   - Discuss target selection strategies
   - Examine malicious attachment delivery

2. **Security Policy Implementation (45 minutes)**
   ```python
   # Demonstrate policy configuration
   policy_manager = PolicyManager("config/security_policies/")
   policy_manager.apply_policy(simulation, "strict_policy")
   
   # Show impact on attack success rates
   results = execute_phishing_scenario(simulation, agents, steps=50)
   analyze_defense_effectiveness(results)
   ```

3. **Hands-on Exercise (20 minutes)**
   - Students modify security policies
   - Test different blocking configurations
   - Compare effectiveness metrics
   - Document observations

4. **Discussion and Analysis (10 minutes)**
   - Review student findings
   - Discuss real-world implications
   - Address questions and concerns

**Student Deliverables:**
- Modified security policy configuration
- Comparative analysis of policy effectiveness
- Documentation of phishing indicators
- Incident response procedure outline

#### Session 3: Advanced Threats and Blue Team Response (2 hours)

**Learning Objectives:**
- Understand advanced persistent threat (APT) methodologies
- Implement comprehensive blue team responses
- Practice multi-agent coordination scenarios
- Develop incident response procedures

**Instructor Activities:**
1. **APT Scenario Demonstration (30 minutes)**
   - Execute full attack chain scenario
   - Analyze C2 beacon installation
   - Discuss data exfiltration techniques
   - Examine lateral movement patterns

2. **Blue Team Response Workshop (60 minutes)**
   ```python
   # Demonstrate blue team agent configuration
   blue_agent = BlueTeamAgent({
       "role": "email_security_analyst",
       "monitoring_scope": ["smtp_server", "email_clients"],
       "response_capabilities": ["block_sender", "quarantine_email", "investigate"]
   })
   
   # Show coordinated response to threats
   response_results = execute_defensive_scenario(simulation, agents, steps=100)
   ```

3. **Student Exercise: Custom Blue Agent (20 minutes)**
   - Students create custom blue team agent
   - Implement specific response procedures
   - Test against attack scenarios
   - Measure response effectiveness

4. **Scenario Analysis and Discussion (10 minutes)**
   - Review defense strategies
   - Discuss improvement opportunities
   - Plan advanced exercises

**Student Deliverables:**
- Custom blue team agent implementation
- Incident response procedure documentation
- Analysis of defense effectiveness metrics
- Recommendations for security improvements

### Teaching Best Practices

#### Effective Demonstration Techniques

**1. Progressive Complexity**
```python
# Start with simple scenarios
def demonstrate_basic_email_flow():
    """Show normal email operations first."""
    # Execute baseline scenario
    # Explain each component
    # Highlight key concepts

# Build to complex attacks
def demonstrate_advanced_apt():
    """Show sophisticated attack chains."""
    # Multi-stage attack progression
    # Defensive countermeasures
    # Real-world implications
```

**2. Interactive Learning**
- Encourage students to modify configurations
- Provide guided exploration opportunities
- Use pair programming for complex exercises
- Implement peer review processes

**3. Real-World Context**
- Connect scenarios to actual security incidents
- Discuss current threat landscape
- Reference industry best practices
- Highlight career relevance

#### Common Teaching Challenges

**Challenge: Students Struggle with Environment Setup**
```bash
# Solution: Provide setup verification script
#!/bin/bash
echo "🔍 Verifying PrimAITE-Mail Environment..."

# Check Python version
python_version=$(python --version 2>&1)
echo "Python: $python_version"

# Check PrimAITE installation
python -c "import primaite; print('✅ PrimAITE installed')" 2>/dev/null || echo "❌ PrimAITE not found"

# Check PrimAITE-Mail installation
python -c "import primaite_mail; print('✅ PrimAITE-Mail installed')" 2>/dev/null || echo "❌ PrimAITE-Mail not found"

# Check Jupyter Lab
jupyter lab --version >/dev/null 2>&1 && echo "✅ Jupyter Lab available" || echo "❌ Jupyter Lab not found"

echo "🎯 Environment verification complete"
```

**Challenge: Complex Request System Confusion**
```python
# Solution: Provide clear examples and patterns
class RequestSystemTutorial:
    """Step-by-step request system tutorial."""
    
    def demonstrate_basic_request(self):
        """Show simplest possible request."""
        # Start with do-nothing action
        response = simulation.apply_request(["network", "node", "hostname", "do_nothing"])
        print(f"Response: {response.status}")
    
    def demonstrate_service_request(self):
        """Show service interaction pattern."""
        # Service requests (background services)
        response = simulation.apply_request([
            "network", "node", "mail_server",
            "service", "smtp-server",
            "list_mailboxes"
        ])
    
    def demonstrate_application_request(self):
        """Show application interaction pattern."""
        # Application requests (user programs)
        response = simulation.apply_request([
            "network", "node", "client_workstation",
            "application", "email-client",
            "send_email",
            {"sender": "user@company.com", "recipient": "target@company.com"}
        ])
```

**Challenge: Testing and Debugging Difficulties**
```bash
# Solution: Provide debugging workflow
cd PrimAITE-Mail/tests

# Use test runner for output capture
./run_test.sh "python -c 'print(\"Hello World\")'"

# Check output file
ls test_output/
cat test_output/test_run_*.txt

# Debug specific issues
./run_test.sh "python -m pytest unit_tests/test_specific.py -v -s"
```

## Assessment Rubrics

### Cybersecurity Knowledge Assessment

#### Email Security Concepts (25 points)

**Excellent (23-25 points):**
- Demonstrates comprehensive understanding of email attack vectors
- Accurately identifies phishing techniques and social engineering methods
- Explains malicious attachment delivery and C2 beacon installation
- Describes business email compromise and financial fraud schemes
- Analyzes advanced persistent threat methodologies

**Proficient (18-22 points):**
- Shows good understanding of basic email security threats
- Identifies common phishing indicators and attack patterns
- Explains attachment-based attacks and malware delivery
- Understands basic incident response procedures
- Recognizes security policy importance

**Developing (13-17 points):**
- Demonstrates basic awareness of email security issues
- Identifies obvious phishing attempts
- Understands simple security measures
- Shows limited knowledge of attack methodologies
- Requires guidance for complex concepts

**Inadequate (0-12 points):**
- Shows minimal understanding of email security
- Cannot identify basic threats or attacks
- Lacks knowledge of security measures
- Requires significant remediation

#### Defense Implementation (25 points)

**Excellent (23-25 points):**
- Implements comprehensive email security policies
- Configures effective blocking rules and content filtering
- Designs appropriate incident response procedures
- Optimizes security configurations based on metrics
- Demonstrates advanced blue team coordination

**Proficient (18-22 points):**
- Implements basic security policies correctly
- Configures sender and IP blocking effectively
- Creates functional incident response procedures
- Uses metrics to evaluate defense effectiveness
- Shows understanding of blue team operations

**Developing (13-17 points):**
- Implements simple security measures
- Configures basic blocking rules
- Creates limited incident response procedures
- Shows basic understanding of defense metrics
- Requires guidance for complex configurations

**Inadequate (0-12 points):**
- Cannot implement effective security measures
- Fails to configure basic protections
- Shows no understanding of incident response
- Requires significant support

### PrimAITE Development Skills Assessment

#### Technical Implementation (25 points)

**Excellent (23-25 points):**
- Demonstrates mastery of PrimAITE request system
- Implements complex agent behaviors correctly
- Uses proper tree navigation and parameter passing
- Follows all coding standards and best practices
- Creates comprehensive test suites

**Proficient (18-22 points):**
- Uses PrimAITE request system correctly
- Implements basic agent behaviors
- Follows most coding standards
- Creates adequate test coverage
- Shows good understanding of architecture

**Developing (13-17 points):**
- Shows basic understanding of request system
- Implements simple agent modifications
- Follows some coding standards
- Creates limited tests
- Requires guidance for complex implementations

**Inadequate (0-12 points):**
- Cannot use request system effectively
- Fails to implement working code
- Does not follow coding standards
- No meaningful test coverage

#### Problem-Solving and Debugging (25 points)

**Excellent (23-25 points):**
- Independently identifies and resolves complex issues
- Uses systematic debugging approaches
- Implements effective error handling
- Optimizes performance and reliability
- Helps others with troubleshooting

**Proficient (18-22 points):**
- Resolves most issues with minimal guidance
- Uses basic debugging techniques
- Implements adequate error handling
- Shows good problem-solving skills
- Can troubleshoot common problems

**Developing (13-17 points):**
- Resolves simple issues independently
- Uses limited debugging techniques
- Requires guidance for complex problems
- Shows basic problem-solving skills
- Needs help with troubleshooting

**Inadequate (0-12 points):**
- Cannot resolve issues independently
- Shows no systematic debugging approach
- Requires constant assistance
- Poor problem-solving skills

### Assessment Methods

#### Practical Exercises (40% of grade)
- Hands-on implementation assignments
- Configuration modification tasks
- Agent development projects
- Security policy creation exercises

#### Project Work (35% of grade)
- Custom scenario development
- Comprehensive testing implementation
- Documentation and presentation
- Peer review and collaboration

#### Knowledge Demonstration (25% of grade)
- Technical presentations
- Code review participation
- Troubleshooting assistance to peers
- Written analysis and reflection

## Student Exercises

### Exercise 1: Basic Email Security Configuration

**Objective:** Configure basic email security policies and measure their effectiveness.

**Prerequisites:**
- Working PrimAITE-Mail environment
- Completed baseline scenario execution
- Understanding of YAML configuration format

**Instructions:**

1. **Create Custom Security Policy**
   ```yaml
   # Create config/security_policies/student_policy.yaml
   smtp_security_policies:
     student_policy:
       name: "student_custom_policy"
       description: "Custom policy created by [student_name]"
       
       sender_blocking:
         enabled: true
         blocked_senders:
           - "spam@malicious.com"
           - "phishing@evil.org"
         blocked_domains:
           - "malicious.com"
           - "suspicious-site.net"
       
       attachment_policies:
         enabled: true
         blocked_extensions:
           - "exe"
           - "scr"
           - "bat"
         max_attachment_size_mb: 20
   ```

2. **Test Policy Effectiveness**
   ```python
   # Execute in notebook cell
   from primaite_mail.config.policy_manager import PolicyManager
   
   # Load and apply custom policy
   policy_manager = PolicyManager("config/security_policies/student_policy.yaml")
   policy_manager.apply_policy(simulation, "student_policy")
   
   # Execute phishing scenario with custom policy
   results = execute_phishing_scenario(simulation, agents, steps=50)
   
   # Analyze results
   print(f"Blocked emails: {results['blocked_count']}")
   print(f"Success rate: {results['attack_success_rate']:.2%}")
   ```

3. **Compare with Baseline**
   - Execute same scenario with baseline policy
   - Document differences in effectiveness
   - Identify strengths and weaknesses of custom policy

**Deliverables:**
- Custom security policy YAML file
- Comparative analysis report (500 words)
- Screenshots of metrics dashboards
- Recommendations for policy improvements

**Assessment Criteria:**
- Policy configuration correctness (25%)
- Effectiveness analysis quality (35%)
- Documentation completeness (25%)
- Improvement recommendations (15%)

### Exercise 2: Green Team Agent Development

**Objective:** Create a custom green team agent with realistic behavior patterns.

**Prerequisites:**
- Understanding of agent configuration structure
- Basic Python programming skills
- Familiarity with PrimAITE request system

**Instructions:**

1. **Design Agent Profile**
   ```yaml
   # Create config/agents/custom_green_agent.yaml
   green_team_agents:
     marketing_intern:
       name: "marketing_intern"
       email_address: "intern@company.com"
       node_name: "intern_workstation"
       role: "marketing_intern"
       
       behavior_patterns:
         send_probability: 0.4      # High email activity
         retrieve_probability: 0.9  # Constantly checking email
         attachment_probability: 0.2 # Limited attachment usage
         external_comm_probability: 0.1 # Mostly internal communication
       
       email_templates:
         - template_type: "internal_communication"
           subject_patterns:
             - "Question about {topic}"
             - "Need help with {task}"
             - "Status update on {project}"
           body_patterns:
             - "Hi team,\n\nI have a question about..."
             - "Could someone help me with..."
           recipient_lists:
             - "marketing_team"
             - "supervisors"
       
       security_awareness:
         phishing_susceptibility: 0.6  # Higher risk (inexperienced)
         attachment_caution: 0.4
         external_sender_trust: 0.7
   ```

2. **Implement Agent Behavior**
   ```python
   # Create custom agent class
   from primaite_mail.game.agents.green_mail_agent import GreenMailAgent
   
   class MarketingInternAgent(GreenMailAgent):
       """Custom green team agent representing marketing intern."""
       
       def __init__(self, config):
           super().__init__(config)
           self.experience_level = "beginner"
           self.supervision_required = True
       
       def select_action(self, current_step):
           """Override action selection for intern-specific behavior."""
           
           # Interns are more likely to ask questions
           if self.needs_help():
               return self.create_help_request_action()
           
           # Standard behavior with modifications
           return super().select_action(current_step)
       
       def needs_help(self):
           """Determine if intern needs to ask for help."""
           import random
           return random.random() < 0.3  # 30% chance of needing help
   ```

3. **Test Agent Integration**
   ```python
   # Add agent to simulation
   intern_agent = MarketingInternAgent(intern_config)
   agents['marketing_intern'] = intern_agent
   
   # Execute scenario with custom agent
   results = execute_baseline_scenario(simulation, agents, steps=30)
   
   # Analyze agent behavior
   intern_actions = results['agent_actions']['marketing_intern']
   print(f"Intern sent {intern_actions['emails_sent']} emails")
   print(f"Help requests: {intern_actions['help_requests']}")
   ```

**Deliverables:**
- Agent configuration YAML file
- Custom agent class implementation
- Integration test results
- Behavior analysis report (750 words)

**Assessment Criteria:**
- Configuration accuracy (20%)
- Code quality and functionality (35%)
- Integration success (20%)
- Behavior analysis depth (25%)

### Exercise 3: Red Team Attack Scenario

**Objective:** Develop a custom red team attack scenario with multiple phases.

**Prerequisites:**
- Understanding of attack methodologies
- Advanced PrimAITE request system knowledge
- Experience with multi-agent scenarios

**Instructions:**

1. **Design Attack Campaign**
   ```python
   class CustomPhishingCampaign:
       """Multi-phase phishing campaign implementation."""
       
       def __init__(self, target_profiles):
           self.target_profiles = target_profiles
           self.attack_phase = "reconnaissance"
           self.intelligence = {}
           self.compromised_targets = set()
       
       def execute_reconnaissance(self, simulation, step):
           """Phase 1: Gather intelligence on targets."""
           # Implement target profiling logic
           # Collect email addresses and behavioral patterns
           # Identify high-value targets
           pass
       
       def execute_initial_access(self, simulation, step):
           """Phase 2: Launch targeted phishing attacks."""
           # Generate contextual phishing emails
           # Deploy malicious attachments
           # Track user interactions
           pass
       
       def execute_post_compromise(self, simulation, step):
           """Phase 3: Post-compromise activities."""
           # Install C2 beacons
           # Exfiltrate data
           # Maintain persistence
           pass
   ```

2. **Implement Attack Logic**
   - Create realistic phishing email templates
   - Implement target selection algorithms
   - Design malicious attachment simulation
   - Add adaptive behavior based on defensive responses

3. **Test Against Defenses**
   ```python
   # Execute attack against different security policies
   policies = ["baseline_policy", "strict_policy", "permissive_policy"]
   
   for policy in policies:
       # Apply security policy
       policy_manager.apply_policy(simulation, policy)
       
       # Execute attack campaign
       campaign = CustomPhishingCampaign(target_profiles)
       results = campaign.execute_full_campaign(simulation, agents, steps=100)
       
       # Record effectiveness metrics
       effectiveness[policy] = results['success_metrics']
   ```

**Deliverables:**
- Complete attack scenario implementation
- Multi-phase attack logic
- Effectiveness analysis against different policies
- Technical documentation (1000 words)
- Demonstration video (5 minutes)

**Assessment Criteria:**
- Attack realism and sophistication (30%)
- Technical implementation quality (25%)
- Effectiveness analysis depth (25%)
- Documentation and presentation (20%)

## Common Pitfalls and Solutions

### PrimAITE-Mail Development Pitfalls

#### 1. Request System Misunderstandings

**Pitfall: Incorrect Parameter Placement**
```python
# ❌ WRONG: Parameters in context dictionary
response = simulation.apply_request(
    request=["network", "node", "hostname", "service", "smtp-server", "send_email"],
    context={"sender": "alice@company.com", "recipient": "bob@company.com"}
)
# Results in: IndexError: list index out of range

# ✅ CORRECT: Parameters in request list
response = simulation.apply_request(
    request=["network", "node", "hostname", "service", "smtp-server", "send_email", 
             {"sender": "alice@company.com", "recipient": "bob@company.com"}],
    context={}
)
```

**Solution Pattern:**
```python
def create_email_request(node_name, email_data):
    """Helper function to create properly formatted email requests."""
    return [
        "network", "node", node_name,
        "application", "email-client",
        "send_email",
        {
            "sender": email_data["sender"],
            "recipient": email_data["recipient"],
            "subject": email_data.get("subject", ""),
            "body": email_data.get("body", ""),
            "attachments": email_data.get("attachments", [])
        }
    ]
```

#### 2. Service vs Application Confusion

**Pitfall: Wrong Component Type**
```python
# ❌ WRONG: Email client is an application, not a service
response = simulation.apply_request([
    "network", "node", "client_workstation",
    "service", "email-client",  # Should be "application"
    "send_email", params
])
# Results in: RequestResponse with status "unreachable"

# ✅ CORRECT: Use proper component type
response = simulation.apply_request([
    "network", "node", "client_workstation",
    "application", "email-client",  # Correct component type
    "send_email", params
])
```

**Memory Aid:**
- **Services**: Background processes (smtp-server, pop3-server, dns-server)
- **Applications**: User programs (email-client, web-browser, text-editor)

#### 3. Attribute Name Errors

**Pitfall: Using Deprecated Attributes**
```python
# ❌ WRONG: Deprecated attribute names
node_health = node.health_state  # AttributeError
link_start = link.node_a          # AttributeError
link_end = link.node_b            # AttributeError

# ✅ CORRECT: Current attribute names
node_health = node.health_state_actual
link_start = link.endpoint_a
link_end = link.endpoint_b
```

**Solution: Attribute Verification Helper**
```python
def verify_attributes(obj, expected_attrs):
    """Verify object has expected attributes."""
    missing = []
    for attr in expected_attrs:
        if not hasattr(obj, attr):
            missing.append(attr)
    
    if missing:
        available = [attr for attr in dir(obj) if not attr.startswith('_')]
        print(f"Missing attributes: {missing}")
        print(f"Available attributes: {available}")
    
    return len(missing) == 0

# Usage
verify_attributes(node, ['health_state_actual', 'hostname', 'ip_address'])
verify_attributes(link, ['endpoint_a', 'endpoint_b', 'bandwidth'])
```

#### 4. Agent Action Timing Issues

**Pitfall: Manual Action Calls**
```python
# ❌ WRONG: Calling get_action() manually before game.step()
agent = GreenMailAgent(config)
action = agent.get_action()  # Don't do this!
response = game.step({agent_name: action})
# Results in: Empty mailboxes, timing conflicts

# ✅ CORRECT: Let game loop handle action selection
game = PrimaiteGame.from_config(config)
response = game.step()  # Game calls agent.get_action() automatically
```

**Solution: Proper Game Loop Usage**
```python
def execute_scenario_correctly(game, steps):
    """Execute scenario with proper game loop usage."""
    results = []
    
    for step in range(steps):
        # Game automatically calls agent.get_action() for all agents
        step_result = game.step()
        results.append(step_result)
        
        # Process results after step completion
        process_step_results(step_result, step)
    
    return results
```

#### 5. Testing Output Capture Issues

**Pitfall: Direct Command Execution**
```bash
# ❌ WRONG: Direct execution may trigger safety clauses
python -m pytest tests/ -v > results.txt 2>&1
# May not capture output properly in some environments

# ✅ CORRECT: Use test runner script
cd tests/
./run_test.sh "python -m pytest unit_tests/ -v"
# Automatically captures output to timestamped files
```

**Solution: Test Runner Usage Pattern**
```bash
#!/bin/bash
# Always use from tests/ directory

# Single test file
./run_test.sh "python -m pytest unit_tests/test_email_security.py -v"

# Specific test method
./run_test.sh "python -m pytest unit_tests/test_agents.py::TestGreenAgent::test_email_sending -v"

# All tests with coverage
./run_test.sh "python -m pytest --cov=primaite_mail --cov-report=html"

# Check results
ls test_output/
cat test_output/test_run_$(date +%Y%m%d)_*.txt
```

### Debugging Workflow

#### Systematic Debugging Approach

**1. Environment Verification**
```python
def verify_environment():
    """Verify PrimAITE-Mail environment is properly set up."""
    checks = []
    
    # Check Python environment
    import sys
    checks.append(f"Python version: {sys.version}")
    
    # Check PrimAITE installation
    try:
        import primaite
        checks.append(f"✅ PrimAITE version: {primaite.__version__}")
    except ImportError:
        checks.append("❌ PrimAITE not installed")
    
    # Check PrimAITE-Mail installation
    try:
        import primaite_mail
        checks.append(f"✅ PrimAITE-Mail available")
    except ImportError:
        checks.append("❌ PrimAITE-Mail not installed")
    
    # Check Jupyter environment
    try:
        import jupyter
        checks.append("✅ Jupyter available")
    except ImportError:
        checks.append("❌ Jupyter not installed")
    
    for check in checks:
        print(check)
    
    return all("✅" in check for check in checks)
```

**2. Request System Debugging**
```python
def debug_request(simulation, request):
    """Debug request execution step by step."""
    print(f"🔍 Debugging request: {request}")
    
    # Validate request structure
    if not isinstance(request, list):
        print("❌ Request must be a list")
        return
    
    if len(request) < 2:
        print("❌ Request too short")
        return
    
    # Check if parameters are in correct position
    if len(request) > 1 and isinstance(request[-1], dict):
        print(f"✅ Parameters found: {request[-1]}")
    else:
        print("⚠️ No parameters or parameters not in last position")
    
    # Attempt request execution
    try:
        response = simulation.apply_request(request)
        print(f"✅ Request successful: {response.status}")
        if response.data:
            print(f"📊 Response data: {response.data}")
    except Exception as e:
        print(f"❌ Request failed: {e}")
        
        # Provide debugging suggestions
        if "IndexError" in str(e):
            print("💡 Suggestion: Check parameter placement (should be last in request list)")
        elif "unreachable" in str(e):
            print("💡 Suggestion: Check component type (service vs application)")
        elif "AttributeError" in str(e):
            print("💡 Suggestion: Check attribute names (health_state_actual, endpoint_a/b)")
```

**3. Agent Behavior Debugging**
```python
def debug_agent_behavior(agent, simulation, steps=5):
    """Debug agent behavior over multiple steps."""
    print(f"🔍 Debugging agent: {agent.name}")
    
    for step in range(steps):
        print(f"\n--- Step {step + 1} ---")
        
        # Check agent state
        print(f"Agent email: {getattr(agent, 'email_address', 'Not set')}")
        print(f"Agent node: {getattr(agent, 'node_name', 'Not set')}")
        
        # Get action
        try:
            action = agent.get_action()
            print(f"Selected action: {action}")
            
            # Form request
            if hasattr(agent, 'action_manager'):
                request = agent.action_manager.form_request(action[0], action[1])
                print(f"Formed request: {request}")
                
                # Execute request
                response = simulation.apply_request(request)
                print(f"Response: {response.status}")
                if response.status != "success":
                    print(f"Error details: {response.data}")
            
        except Exception as e:
            print(f"❌ Action failed: {e}")
            import traceback
            traceback.print_exc()
```

This comprehensive educational and training guide provides instructors and students with the knowledge and tools needed to effectively learn both cybersecurity concepts and PrimAITE development skills through the email security demonstration.