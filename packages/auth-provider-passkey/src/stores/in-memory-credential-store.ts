import type { CredentialStore, StoredCredential } from "../types.js"

/**
 * In-memory CredentialStore for development and single-instance
 * deployments. Credentials are lost on restart — back the store with a
 * database for production use.
 */
export class InMemoryCredentialStore implements CredentialStore {
  private credentials = new Map<string, StoredCredential>()

  public async findById(
    credentialId: string,
  ): Promise<StoredCredential | null> {
    return this.credentials.get(credentialId) ?? null
  }

  public async findByUserId(userId: string): Promise<StoredCredential[]> {
    return [...this.credentials.values()].filter(
      (credential) => credential.userId === userId,
    )
  }

  public async create(
    data: Omit<StoredCredential, "createdAt" | "lastUsedAt">,
  ): Promise<StoredCredential> {
    const credential: StoredCredential = { ...data, createdAt: new Date() }
    this.credentials.set(credential.credentialId, credential)
    return credential
  }

  public async updateCounterAndLastUsed(
    credentialId: string,
    counter: number,
  ): Promise<void> {
    const credential = this.credentials.get(credentialId)
    if (!credential) return
    credential.counter = counter
    credential.lastUsedAt = new Date()
  }

  public async delete(credentialId: string): Promise<void> {
    this.credentials.delete(credentialId)
  }
}
