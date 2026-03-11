export function getErrorMessage(error: unknown) {
	if (error instanceof Error) return error.message
	return String(error)
}

export function getCsrfToken(): string {
	const match = document.cookie.match(/(?:^|;\s*)csrftoken=([^\s;]+)/);
	return match ? match[1] : "";
}