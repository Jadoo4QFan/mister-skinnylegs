"""
Plugin for recovering Roblox platform chat ("thread") artifacts from browser
Cache data.

The Roblox website's chat feature caches responses from the platform-chat-api
hosted on apis.roblox.com. The following endpoints are currently processed:

* /platform-chat-api/v<version>/get-user-conversations - the signed-in user's
  conversation listing. Each conversation entry includes participant details
  (user_data), conversation metadata and the most recent message(s).
* /platform-chat-api/v<version>/get-conversation-messages - a page of messages
  for a single conversation, identified by the conversation_id URL parameter.

Note that Roblox marks messages/conversations which can no longer be displayed
in the app (e.g. because a participant deleted their account or failed an age
check) with a "visibility" of "hidden" or "invalid" rather than removing them
from the responses entirely, so content can still be recovered from the Cache
which the web app would not have shown the user.
"""
import datetime
import json
import re
import urllib.parse

from mister_skinnylegs.util.artifact_utils import ArtifactResult, ArtifactSpec, LogFunction, ReportPresentation, ArtifactStorage
from mister_skinnylegs.util.profile_folder_protocols import BrowserProfileProtocol


CONVERSATIONS_API_URL_PATTERN = re.compile(r"apis\.roblox\.com/platform-chat-api/v\d+/get-user-conversations")
CONVERSATION_MESSAGES_API_URL_PATTERN = re.compile(r"apis\.roblox\.com/platform-chat-api/v\d+/get-conversation-messages")

EPOCH = datetime.datetime(1970, 1, 1)


def _decode_unix_ms(ms) -> datetime.datetime:
    return EPOCH + datetime.timedelta(milliseconds=ms)


def _load_cache_json(cache_rec, log_func: LogFunction, endpoint: str):
    """
    Parses the body of a cache record as JSON, logging and returning None if
    the record has no data or cannot be parsed (e.g. partial/truncated cache
    entries are not uncommon).
    """
    if cache_rec.data is None:
        log_func(f"Warning: Roblox {endpoint} cache record has no data (size zero?). Skipping: {cache_rec.key.url}")
        return None
    try:
        return json.loads(cache_rec.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        log_func(f"Warning: could not parse Roblox {endpoint} cache record as JSON ({e}). Skipping: {cache_rec.data_location}")
        return None


def _conversation_id_from_url(url: str):
    """
    Extracts the conversation_id URL parameter from a get-conversation-messages
    cache key URL.
    """
    try:
        query = urllib.parse.urlparse(url).query
        conversation_ids = urllib.parse.parse_qs(query).get("conversation_id", [])
        return conversation_ids[0] if conversation_ids else None
    except ValueError:
        return None


def _format_username(user_record: dict):
    """
    Formats a user_data entry as a readable name ("username" or
    "username (display name)" where the two differ).
    """
    username = user_record.get("name")
    display_name = user_record.get("display_name")
    if display_name and display_name != username:
        return f"{username} ({display_name})"
    return username


def _format_user(user_id, user_data: dict) -> str:
    """
    Formats a participant user id, adding the name from the conversation's
    user_data where it is available.
    """
    user_record = user_data.get(str(user_id))
    if not isinstance(user_record, dict):
        return str(user_id)
    if username := _format_username(user_record):
        return f"{user_id} ({username})"
    return str(user_id)


def _message_to_row(message: dict, conversation_id, sender_lookup: dict[str, str],
                    source_endpoint: str, cache_rec) -> dict:
    sender_user_id = message.get("sender_user_id")
    replies_to = message.get("replies_to")
    if isinstance(replies_to, dict):
        # the exact shape of a populated replies_to is not currently evidenced;
        # keep whatever identifier-like value we can find, else the raw JSON
        replies_to = replies_to.get("id") or replies_to.get("message_id") or json.dumps(replies_to)
    return {
        "conversation id": conversation_id,
        "message id": message.get("id"),
        "timestamp": message.get("created_at"),
        "sender user id": sender_user_id,
        "sender name": sender_lookup.get(str(sender_user_id)) if sender_user_id is not None else None,
        "content": message.get("content"),
        "message type": message.get("type"),
        "moderation type": message.get("moderation_type"),
        "visibility": message.get("visibility"),
        "is deleted": message.get("is_deleted"),
        "is previewable": message.get("is_previewable"),
        "is badgeable": message.get("is_badgeable"),
        "replies to": replies_to,
        "source endpoint": source_endpoint,
        "cache url": cache_rec.key.url,
        "data location": f"{cache_rec.data_location}",
    }


def _iter_conversations(profile: BrowserProfileProtocol, log_func: LogFunction):
    """
    Yields (cache_rec, conversation) tuples for each conversation entry found
    in cached get-user-conversations responses.
    """
    for cache_rec in profile.iterate_cache(url=CONVERSATIONS_API_URL_PATTERN):
        cache_data = _load_cache_json(cache_rec, log_func, "get-user-conversations")
        if cache_data is None:
            continue
        conversations = cache_data.get("conversations")
        if not isinstance(conversations, list):
            log_func(f"Warning: unexpected structure in Roblox get-user-conversations cache record "
                     f"(no conversations list). Skipping: {cache_rec.data_location}")
            continue
        for conversation in conversations:
            if isinstance(conversation, dict):
                yield cache_rec, conversation
            else:
                log_func(f"Warning: unexpected conversation entry in Roblox get-user-conversations cache "
                         f"record. Skipping: {cache_rec.data_location}")


def get_user_conversations(profile: BrowserProfileProtocol, log_func: LogFunction,
                           storage: ArtifactStorage) -> ArtifactResult:
    results = []
    # The same conversation may be recovered from multiple cached listings
    # (re-fetches); identical snapshots are collapsed, but distinct snapshots
    # (e.g. different updated_at) are all reported as each is a separate
    # recovery point.
    seen_snapshots = set()

    for cache_rec, conversation in _iter_conversations(profile, log_func):
        conversation_id = conversation.get("id")
        updated_at = conversation.get("updated_at")
        snapshot_key = (str(conversation_id), str(updated_at))
        if snapshot_key in seen_snapshots:
            continue
        seen_snapshots.add(snapshot_key)

        participants = conversation.get("participant_user_ids") or []
        user_data = conversation.get("user_data") or {}

        preview_message = conversation.get("preview_message")
        if not isinstance(preview_message, dict):
            messages = conversation.get("messages") or []
            preview_message = messages[0] if messages and isinstance(messages[0], dict) else None

        sort_index = conversation.get("sort_index")

        results.append({
            "conversation id": conversation_id,
            "conversation type": conversation.get("type"),
            "name": conversation.get("name"),
            "is default name": conversation.get("is_default_name"),
            "created by user id": conversation.get("created_by"),
            "participants": ", ".join(_format_user(p, user_data) for p in participants),
            "created at": conversation.get("created_at"),
            "updated at": updated_at,
            "last activity": _decode_unix_ms(sort_index) if isinstance(sort_index, (int, float)) else None,
            "unread message count": conversation.get("unread_message_count"),
            "moderation type": conversation.get("moderation_type"),
            "user pending status": conversation.get("user_pending_status"),
            "participant pending status": conversation.get("participant_pending_status"),
            "osa acknowledgement status": conversation.get("osa_acknowledgement_status"),
            "user opted into chat messages": conversation.get("user_opted_into_chat_messages"),
            "latest message content": preview_message.get("content") if preview_message else None,
            "latest message timestamp": preview_message.get("created_at") if preview_message else None,
            "latest message sender": _format_user(preview_message["sender_user_id"], user_data)
                if preview_message and preview_message.get("sender_user_id") is not None else None,
            "cache url": cache_rec.key.url,
            "data location": f"{cache_rec.data_location}",
        })

    results.sort(key=lambda r: r["last activity"] or EPOCH, reverse=True)
    return ArtifactResult(results)


def get_conversation_messages(profile: BrowserProfileProtocol, log_func: LogFunction,
                              storage: ArtifactStorage) -> ArtifactResult:
    # Build a user id -> name lookup from the cached conversation listings so
    # that recovered messages can be attributed by name as well as by id.
    sender_lookup: dict[str, str] = {}
    for _, conversation in _iter_conversations(profile, log_func):
        for user_id, user_record in (conversation.get("user_data") or {}).items():
            if isinstance(user_record, dict) and (username := _format_username(user_record)):
                sender_lookup.setdefault(str(user_id), username)

    results = []
    # Messages can be recovered both from cached conversation listings (which
    # embed the most recent message(s)) and from cached get-conversation-messages
    # pages, which may overlap. Duplicates (same conversation and message id)
    # are collapsed - Roblox chat messages are not editable, so the first
    # recovery is representative.
    seen_messages = set()
    duplicate_count = 0

    def add_messages(messages, conversation_id, source_endpoint: str, cache_rec):
        nonlocal duplicate_count
        for message in messages:
            if not isinstance(message, dict) or message.get("id") is None:
                log_func(f"Warning: skipping unexpected message entry in Roblox {source_endpoint} "
                         f"cache record: {cache_rec.data_location}")
                continue
            message_key = (str(conversation_id), str(message["id"]))
            if message_key in seen_messages:
                duplicate_count += 1
                continue
            seen_messages.add(message_key)
            results.append(_message_to_row(
                message, conversation_id, sender_lookup, source_endpoint, cache_rec))

    for cache_rec, conversation in _iter_conversations(profile, log_func):
        add_messages(conversation.get("messages") or [], conversation.get("id"),
                     "get-user-conversations", cache_rec)

    for cache_rec in profile.iterate_cache(url=CONVERSATION_MESSAGES_API_URL_PATTERN):
        cache_data = _load_cache_json(cache_rec, log_func, "get-conversation-messages")
        if cache_data is None:
            continue
        conversation_id = _conversation_id_from_url(cache_rec.key.url)
        if conversation_id is None:
            log_func(f"Warning: could not extract conversation_id from Roblox get-conversation-messages "
                     f"URL. Messages will have no conversation id: {cache_rec.key.url}")
        add_messages(cache_data.get("messages") or [], conversation_id,
                     "get-conversation-messages", cache_rec)

    if duplicate_count:
        log_func(f"Note: skipped {duplicate_count} duplicate Roblox message record(s) already recovered from the Cache.")

    results.sort(key=lambda r: (str(r["conversation id"]), str(r["timestamp"]), str(r["message id"])))
    return ArtifactResult(results)


def get_chat_users(profile: BrowserProfileProtocol, log_func: LogFunction,
                   storage: ArtifactStorage) -> ArtifactResult:
    users: dict[str, dict] = {}

    for cache_rec, conversation in _iter_conversations(profile, log_func):
        conversation_id = conversation.get("id")
        for user_id, user_record in (conversation.get("user_data") or {}).items():
            if not isinstance(user_record, dict):
                continue
            row = users.get(str(user_id))
            if row is None:
                row = {
                    "user id": user_record.get("id", user_id),
                    "username": user_record.get("name"),
                    "display name": user_record.get("display_name"),
                    "combined name": user_record.get("combined_name"),
                    "is verified": user_record.get("is_verified"),
                    "seen in conversations": [],
                    "data location": f"{cache_rec.data_location}",
                }
                users[str(user_id)] = row
            if conversation_id is not None and conversation_id not in row["seen in conversations"]:
                row["seen in conversations"].append(conversation_id)

    results = list(users.values())
    for row in results:
        row["seen in conversations"] = ", ".join(str(c) for c in row["seen in conversations"])

    def sort_key(row):
        user_id = str(row["user id"])
        return (0, int(user_id), "") if user_id.isdigit() else (1, 0, user_id)

    results.sort(key=sort_key)
    return ArtifactResult(results)


__artifacts__ = (
    ArtifactSpec(
        "Roblox",
        "Roblox Chat Conversations",
        "Recovers Roblox platform chat conversations (threads) from get-user-conversations responses in the Cache",
        "0.1",
        get_user_conversations,
        ReportPresentation.table
    ),
    ArtifactSpec(
        "Roblox",
        "Roblox Chat Messages",
        "Recovers Roblox platform chat messages from get-conversation-messages (and conversation listing) responses in the Cache",
        "0.1",
        get_conversation_messages,
        ReportPresentation.table
    ),
    ArtifactSpec(
        "Roblox",
        "Roblox Chat Users",
        "Recovers Roblox chat participant details from get-user-conversations responses in the Cache",
        "0.1",
        get_chat_users,
        ReportPresentation.table
    ),
)
