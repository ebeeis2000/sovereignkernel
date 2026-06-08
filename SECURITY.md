# Beveiligingsbeleid

## Ondersteunde Versies

| Versie | Ondersteund |
|--------|-------------|
| 0.3.x  | ✅ Actief   |
| < 0.3  | ❌ Niet ondersteund |

## Een kwetsbaarheid melden

**Meld beveiligingsproblemen NIET via publieke GitHub Issues.**

### Responsible Disclosure

1. Stuur een e-mail naar: **anoadder@gmail.com**
2. Onderwerp: `[SECURITY] SovereignKernel — <korte omschrijving>`
3. Vermeld:
   - Beschrijving van de kwetsbaarheid
   - Stappen om te reproduceren
   - Mogelijke impact
   - Eventuele voorgestelde fix

### Reactietijd

- **Ontvangstbevestiging:** binnen 48 uur
- **Eerste beoordeling:** binnen 7 dagen
- **Fix gepland:** binnen 30 dagen (kritiek: 7 dagen)

### Wat verwachten we

- Geef ons redelijke tijd om te reageren voordat je publiceert
- Maak geen misbruik van gevonden kwetsbaarheden
- Verwijder/wijzig geen data van andere gebruikers

### Wat bieden we

- Erkenning in de release notes (tenzij anonimiteit gewenst)
- Directe communicatie over de voortgang van de fix

## Beveiligingsarchitectuur

Zie [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) voor het volledige beveiligingsoverzicht inclusief:
- Cryptografische primitieven en hun parameters
- Key management lifecycle
- Threat model en beveiligingslagen
- Audit en monitoring

## Bekende Beperkingen

- Software-modus (zonder TPM) biedt minder bescherming tegen cold-boot aanvallen
- Electron UI draait in user-space en is vatbaar voor memory-dump attacks op ontgrendelde staat
- Named pipe communicatie is beperkt tot localhost (geen remote access)
