"""
reviewer/agent.py: The Reviewer Agent, a non-executing agent that assesses proposed actions.
"""

import logging
import json
from typing import Dict, Any, List, Optional, Literal

from llm.client import LLMClient # Reviewer Agent has its own LLM client
from schemas.action import LLMInternalAction, ToolMetadata, ReviewerFeedback # Import ReviewerFeedback
from config.settings import settings # For reviewer specific LLM settings
from pydantic import ValidationError # For validating ReviewerFeedback

logger = logging.getLogger(__name__)

# --- Reviewer Agent's LLM Prompting ---
REVIEWER_SYSTEM_PROMPT = """Bạn là Reviewer Agent, một chuyên gia bảo mật có kinh nghiệm với vai trò giám sát hoạt động của Primary Agent. Nhiệm vụ của bạn là đánh giá các hành động được Primary Agent đề xuất để đảm bảo chúng an toàn, hiệu quả và nằm trong phạm vi.

Nguyên tắc bắt buộc:
1.  **Chỉ đọc, không thực thi**: Bạn CHỈ ĐƯA RA ĐÁNH GIÁ và khuyến nghị. Bạn KHÔNG BAO GIỜ THỰC HIỆN bất kỳ hành động nào, gọi công cụ MCP, hoặc sửa đổi trạng thái.
2.  **Định dạng đầu ra nghiêm ngặt**: Bạn PHẢI LUÔN LUÔN trả về đầu ra JSON hợp lệ, tuân thủ schema ReviewerFeedback. KHÔNG BAO GIỜ bao gồm bất kỳ văn bản giải thích, dấu markdown, hoặc các ký tự khác ngoài đối tượng JSON.
3.  **Quyết định rõ ràng**: Đánh giá của bạn phải rõ ràng: "approve", "caution", hoặc "block".
4.  **Lý do ngắn gọn**: Cung cấp một lý do ngắn gọn nhưng đầy đủ cho quyết định của bạn.
5.  **An toàn là trên hết**: Ưu tiên an toàn, tuân thủ phạm vi và hiệu quả của các hành động được đề xuất. Hãy chú ý đến các hành động dư thừa, rủi ro logic hoặc vi phạm phạm vi.

Schema JSON bắt buộc:
```json
{{REVIEWER_FEEDBACK_SCHEMA}}
```
"""

REVIEWER_PLANNING_PROMPT_TEMPLATE = """
Dưới đây là thông tin về một hành động được Primary Agent đề xuất để bạn xem xét:

Mục tiêu chính của cuộc đánh giá:
{{OBJECTIVE}}

Trạng thái đánh giá hiện tại:
```json
{{CURRENT_STATE_JSON}}
```

Các công cụ mà Primary Agent có thể sử dụng (để bạn hiểu ngữ cảnh):
```json
{{AVAILABLE_TOOLS_JSON}}
```

Hành động Primary Agent đề xuất:
```json
{{PROPOSED_ACTION_JSON}}
```

Dựa trên thông tin trên, hãy đưa ra đánh giá của bạn về hành động được đề xuất.
Đánh giá của bạn phải là một đối tượng JSON HỢP LỆ, tuân thủ schema ReviewerFeedback.
"""


class ReviewerAgent:
    """
    A non-executing agent that reviews actions proposed by the Primary Agent.
    It uses its own LLM to assess risks, redundancies, and scope violations.
    """
    def __init__(self):
        # The Reviewer Agent uses a separate LLMClient instance, potentially with different settings
        self.llm_client = LLMClient() 
        logger.info("ReviewerAgent initialized.")

    def review_action(self, 
                      internal_action: LLMInternalAction, 
                      llm_visible_state: Dict[str, Any], 
                      allowed_tools: Dict[str, ToolMetadata]) -> ReviewerFeedback:
        """
        Reviews a proposed LLMInternalAction based on the current state and available tools.
        """
        # Prepare AVAILABLE_TOOLS_JSON for the template
        available_tools_for_llm_json = []
        for tool_name, tool_meta in allowed_tools.items():
            available_tools_for_llm_json.append({
                "name": tool_meta.name,
                "description": tool_meta.description,
                "category": tool_meta.category,
                "risk_level": tool_meta.risk_level,
                "idempotency": tool_meta.idempotency,
                "parameters_schema": tool_meta.parameters_schema.model_dump()
            })
        available_tools_json_str = json.dumps(available_tools_for_llm_json, indent=2)

        # Prepare PROPOSED_ACTION_JSON
        proposed_action_json_str = internal_action.model_dump_json(indent=2)
        
        # Prepare REVIEWER_FEEDBACK_SCHEMA for the system prompt
        reviewer_feedback_schema_str = json.dumps(ReviewerFeedback.model_json_schema(), indent=2)
        
        system_prompt_content = REVIEWER_SYSTEM_PROMPT.replace("{{REVIEWER_FEEDBACK_SCHEMA}}", reviewer_feedback_schema_str)

        user_prompt_content = REVIEWER_PLANNING_PROMPT_TEMPLATE.format(
            OBJECTIVE=llm_visible_state.get("objective", "N/A"),
            CURRENT_STATE_JSON=json.dumps(llm_visible_state, indent=2),
            AVAILABLE_TOOLS_JSON=available_tools_json_str,
            PROPOSED_ACTION_JSON=proposed_action_json_str
        )
        
        # Call the Reviewer Agent's LLM
        try:
            # The Reviewer's LLM output will be a dictionary matching the schema
            raw_reviewer_output_content = self.llm_client._call_api( # Access protected method for now
                messages=[
                    {"role": "system", "content": system_prompt_content},
                    {"role": "user", "content": user_prompt_content}
                ]
            )['choices'][0]['message']['content'] # Extract content
            
            reviewer_data = json.loads(raw_reviewer_output_content)
            
            # Validate reviewer_data against actual ReviewerFeedback Pydantic model
            return ReviewerFeedback.model_validate(reviewer_data)
        except ValidationError as e:
            logger.error(f"Reviewer Agent LLM returned invalid ReviewerFeedback schema: {e}. Raw content: {raw_reviewer_output_content}")
            return ReviewerFeedback(review_decision="caution", review_reason=f"Reviewer LLM output schema validation failed: {e}")
        except Exception as e:
            logger.error(f"Reviewer Agent LLM call failed or returned malformed JSON: {e}")
            return ReviewerFeedback(review_decision="caution", review_reason=f"Reviewer LLM call error: {e}")