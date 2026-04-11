import pytest
from infra import logging_bucket


def test_logging_bucket_exists_true(monkeypatch):
    monkeypatch.setattr(
        logging_bucket.aws.s3,
        "get_bucket",
        lambda **_kwargs: object(),
    )

    assert logging_bucket._bucket_exists("bucket") is True  # nosec B101


def test_logging_bucket_exists_not_found(monkeypatch):
    def raise_not_found(**_kwargs):
        raise RuntimeError("NoSuchBucket: missing")

    monkeypatch.setattr(logging_bucket.aws.s3, "get_bucket", raise_not_found)

    assert logging_bucket._bucket_exists("missing") is False  # nosec B101


def test_logging_bucket_exists_handles_invoke_not_found(monkeypatch):
    def raise_invoke_error(**_kwargs):
        raise RuntimeError("invoke of aws:s3/getBucket:getBucket returned 404")

    monkeypatch.setattr(logging_bucket.aws.s3, "get_bucket", raise_invoke_error)

    assert logging_bucket._bucket_exists("missing") is False  # nosec B101


def test_logging_bucket_exists_handles_notfound(monkeypatch):
    def raise_not_found(**_kwargs):
        raise RuntimeError("NotFound: bucket does not exist")

    monkeypatch.setattr(logging_bucket.aws.s3, "get_bucket", raise_not_found)

    assert logging_bucket._bucket_exists("missing") is False  # nosec B101


def test_logging_bucket_exists_handles_empty_result(monkeypatch):
    def raise_empty_result(**_kwargs):
        raise RuntimeError("reading S3 Bucket (missing): empty result")

    monkeypatch.setattr(logging_bucket.aws.s3, "get_bucket", raise_empty_result)

    assert logging_bucket._bucket_exists("missing") is False  # nosec B101


def test_logging_bucket_exists_handles_couldnt_find_resource(monkeypatch):
    def raise_missing_resource(**_kwargs):
        raise RuntimeError("couldn't find resource: missing")

    monkeypatch.setattr(
        logging_bucket.aws.s3,
        "get_bucket",
        raise_missing_resource,
    )

    assert logging_bucket._bucket_exists("missing") is False  # nosec B101


def test_logging_bucket_exists_raises_unexpected(monkeypatch):
    def raise_other(**_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(logging_bucket.aws.s3, "get_bucket", raise_other)

    with pytest.raises(RuntimeError) as excinfo:
        logging_bucket._bucket_exists("oops")

    assert str(excinfo.value) == "boom"  # nosec B101
