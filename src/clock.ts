export type Clock = { getTime: () => number }

export function realClock(): Clock {
  return { getTime: () => new Date().getTime() }
}

export function stubClock(time: number): Clock {
  return {
    getTime: () => time
  }
}
