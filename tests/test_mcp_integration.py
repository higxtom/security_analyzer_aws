"""
MCP 統合コンポーネントのユニットテスト
"""
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from src.agent.security_agent import (
    _build_severity_filter,
    _extract_findings_from_output,
    _parse_remediation_output,
    _write_temp_files,
)


# テスト用のサンプル Finding（Security Hub get-findings レスポンス形式）
SAMPLE_FINDING = {
    "Id": "arn:aws:securityhub:ap-northeast-1:123456789012:finding/abc123",
    "Title": "S3 buckets should have block public access enabled",
    "Severity": {"Label": "HIGH", "Normalized": 70},
    "AwsAccountId": "123456789012",
    "Region": "ap-northeast-1",
    "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::my-bucket"}],
}


class TestBuildSeverityFilter:
    def test_builds_correct_filter(self):
        """SeverityLabel フィルタが正しく生成される"""
        result = json.loads(_build_severity_filter(["CRITICAL", "HIGH"]))
        assert len(result["SeverityLabel"]) == 2
        assert result["SeverityLabel"][0] == {"Value": "CRITICAL", "Comparison": "EQUALS"}
        assert result["SeverityLabel"][1] == {"Value": "HIGH", "Comparison": "EQUALS"}
        assert result["RecordState"][0]["Value"] == "ACTIVE"
        assert result["WorkflowStatus"][0]["Value"] == "NEW"

    def test_single_severity(self):
        result = json.loads(_build_severity_filter(["CRITICAL"]))
        assert len(result["SeverityLabel"]) == 1

    def test_empty_severity(self):
        result = json.loads(_build_severity_filter([]))
        assert result["SeverityLabel"] == []


class TestExtractFindingsFromOutput:
    def test_extracts_findings_from_valid_json(self):
        """正常な get-findings レスポンスから Findings を抽出"""
        response = {"Findings": [SAMPLE_FINDING]}
        text = f"Here are the results:\n{json.dumps(response)}\nDone."
        findings = _extract_findings_from_output(text)
        assert len(findings) == 1
        assert findings[0]["Title"] == "S3 buckets should have block public access enabled"

    def test_extracts_multiple_findings(self):
        """複数の Finding を含むレスポンスを抽出"""
        response = {"Findings": [SAMPLE_FINDING, SAMPLE_FINDING]}
        text = json.dumps(response)
        findings = _extract_findings_from_output(text)
        assert len(findings) == 2

    def test_returns_empty_when_no_findings(self):
        """Findings が空の場合は空リストを返す"""
        text = json.dumps({"Findings": []})
        findings = _extract_findings_from_output(text)
        assert findings == []

    def test_returns_empty_on_invalid_json(self):
        """不正な JSON の場合は空リストを返す"""
        text = "This is not JSON at all."
        findings = _extract_findings_from_output(text)
        assert findings == []

    def test_returns_empty_on_no_findings_key(self):
        """Findings キーがない場合は空リストを返す"""
        text = json.dumps({"Items": [{"key": "value"}]})
        findings = _extract_findings_from_output(text)
        assert findings == []

    def test_handles_mixed_text_and_json(self):
        """テキストと JSON が混在する場合も正しく抽出"""
        response = {"Findings": [SAMPLE_FINDING]}
        text = (
            "DynamoDB query result: {\"Items\": []}\n\n"
            f"SecurityHub findings: {json.dumps(response)}\n"
            "All done!"
        )
        findings = _extract_findings_from_output(text)
        assert len(findings) == 1


class TestParseRemediationOutput:
    def test_extracts_yaml_and_sh(self):
        """YAML とシェルスクリプトが正しく抽出される"""
        raw = """
---REMEDIATION_YAML_START---
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  S3Bucket:
    Type: AWS::S3::Bucket
---REMEDIATION_YAML_END---

---COMMANDS_SH_START---
#!/bin/bash
aws s3api put-public-access-block --bucket my-bucket
---COMMANDS_SH_END---
"""
        yaml_content, sh_content = _parse_remediation_output(raw)
        assert "AWSTemplateFormatVersion" in yaml_content
        assert "aws s3api put-public-access-block" in sh_content

    def test_fallback_on_missing_markers(self):
        """マーカーが見つからない場合はフォールバックを返す"""
        yaml_content, sh_content = _parse_remediation_output("no markers here")
        assert "失敗" in yaml_content
        assert "失敗" in sh_content


class TestWriteTempFiles:
    def test_writes_files_correctly(self):
        """一時ファイルが正しく書き出される"""
        with tempfile.TemporaryDirectory() as tmpdir:
            workdir = Path(tmpdir)
            paths = _write_temp_files(
                report_md="# Report",
                remediation_yaml="key: value",
                commands_sh="#!/bin/bash\necho hello",
                workdir=workdir,
            )

            assert len(paths) == 3
            assert Path(paths["report.md"]).read_text() == "# Report"
            assert Path(paths["remediation.yaml"]).read_text() == "key: value"
            assert Path(paths["commands.sh"]).read_text() == "#!/bin/bash\necho hello"


class TestMcpClientModule:
    @patch("src.utils.mcp_client.settings")
    def test_build_server_params(self, mock_settings):
        """MCPサーバーパラメータが正しく構築される"""
        mock_settings.aws_region = "us-east-1"
        mock_settings.aws_profile = None
        mock_settings.mcp_startup_timeout = 60

        from src.utils.mcp_client import _build_server_params

        params = _build_server_params()
        assert params.command == "awslabs.aws-api-mcp-server"
        assert params.env is not None
        assert params.env["AWS_REGION"] == "us-east-1"
        assert "AWS_PROFILE" not in params.env

    @patch("src.utils.mcp_client.settings")
    def test_build_server_params_with_profile(self, mock_settings):
        """AWS Profile が設定されている場合に含まれる"""
        mock_settings.aws_region = "ap-northeast-1"
        mock_settings.aws_profile = "my-profile"
        mock_settings.mcp_startup_timeout = 60

        from src.utils.mcp_client import _build_server_params

        params = _build_server_params()
        assert params.env["AWS_PROFILE"] == "my-profile"
