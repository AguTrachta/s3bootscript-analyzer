from s3bootscript_analyzer.application import get_application_info


def test_get_application_info_returns_scaffold_metadata() -> None:
    application_info = get_application_info()

    assert application_info.name == "s3bootscript-analyzer"
    assert application_info.status == "ready"
